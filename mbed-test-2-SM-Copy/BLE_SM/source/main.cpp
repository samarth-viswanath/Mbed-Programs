/* mbed Microcontroller Library
 * Copyright (c) 2006-2013 ARM Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 
#include <events/mbed_events.h>
#include <mbed.h>
#include "ble/BLE.h"
#include "SecurityManager.h"
#include "pretty_printer.h"
#include <string.h>

#if MBED_CONF_APP_FILESYSTEM_SUPPORT
#include "LittleFileSystem.h"
#include "HeapBlockDevice.h"
#endif //MBED_CONF_APP_FILESYSTEM_SUPPORT


#include "ble/GattClient.h"
#include "ble/DiscoveredService.h"
#include "ble/DiscoveredCharacteristic.h"
#include "ble/CharacteristicDescriptorDiscovery.h"

/** This example demonstrates all the basic setup required
 *  for pairing and setting up link security both as a central and peripheral
 *
 *  The example is implemented as two classes, one for the peripheral and one
 *  for central inheriting from a common base. They are run in sequence and
 *  require a peer device to connect to. During the peripheral device demonstration
 *  a peer device is required to connect. In the central device demonstration
 *  this peer device will be scanned for and connected to - therefore it should
 *  be advertising with the same address as when it connected.
 *
 *  During the test output is written on the serial connection to monitor its
 *  progress.
 */

static const char DEVICE_NAME[] = "SM_device";

/* we have to specify the disconnect call because of ambiguous overloads */
typedef ble_error_t (Gap::*disconnect_call_t)(ble::connection_handle_t, ble::local_disconnection_reason_t);
const static disconnect_call_t disconnect_call = &Gap::disconnect;

/* for demonstration purposes we will store the peer device address
 * of the device that connects to us in the first demonstration
 * so we can use its address to reconnect to it later */
 static uint8_t address[6] = {153, 69, 16, 111, 13, 0}; //uint8_t address[6] = {0, 13, 111, 16, 69, 153};
static ble::address_t peer_address = ble::address_t(&address[0]);
const static ble::address_t _peer_address_nonin;
ble::connection_handle_t _connectionHandle = NULL;
GattAttribute::Handle_t _CCCD = 0;
 
/** Base class for both peripheral and central. The same class that provides
 *  the logic for the application also implements the SecurityManagerEventHandler
 *  which is the interface used by the Security Manager to communicate events
 *  back to the applications. You can provide overrides for a selection of events
 *  your application is interested in.
 */
class SMDevice : private mbed::NonCopyable<SMDevice>,
                 public SecurityManager::EventHandler,
                 public ble::Gap::EventHandler
{
public:
    SMDevice(BLE &ble, events::EventQueue &event_queue, ble::address_t &peer_address) :
        _led1(LED1, 0),
        _ble(ble),
        _event_queue(event_queue),
        _peer_address(peer_address),
        _handle(0),
        _is_connecting(false),
				_found_characteristic(false) { };

    virtual ~SMDevice()
    {
        if (_ble.hasInitialized()) {
            _ble.shutdown();
        }
    };

    /** Start BLE interface initialisation */
    void run()
    {
        ble_error_t error;

        /* to show we're running we'll blink every 500ms */
        _event_queue.call_every(500, this, &SMDevice::blink);

        if (_ble.hasInitialized()) {
            printf("Ble instance already initialised.\r\n");
            return;
        }

        /* this will inform us off all events so we can schedule their handling
         * using our event queue */
        _ble.onEventsToProcess(
            makeFunctionPointer(this, &SMDevice::schedule_ble_events)
        );

        /* handle gap events */
        _ble.gap().setEventHandler(this);

        error = _ble.init(this, &SMDevice::on_init_complete);

        if (error) {
            printf("Error returned by BLE::init.\r\n");
            return;
        }

        /* this will not return until shutdown */
        _event_queue.dispatch_forever();
    };

private:
    /** Override to start chosen activity when initialisation completes */
    virtual void start() = 0;

    /** This is called when BLE interface is initialised and starts the demonstration */
    void on_init_complete(BLE::InitializationCompleteCallbackContext *event)
    {
        ble_error_t error;

        if (event->error) {
            printf("Error during the initialisation\r\n");
            return;
        }

        /* This path will be used to store bonding information but will fallback
         * to storing in memory if file access fails (for example due to lack of a filesystem) */
        const char* db_path = "/fs/bt_sec_db";
        /* If the security manager is required this needs to be called before any
         * calls to the Security manager happen. */
        error = _ble.securityManager().init(
            true,
            false,
            SecurityManager::IO_CAPS_NONE,
            NULL,
            false,
            db_path
        );

        if (error) {
            printf("Error during init %d\r\n", error);
            return;
        }

        error = _ble.securityManager().preserveBondingStateOnReset(true);

        if (error) {
            printf("Error during preserveBondingStateOnReset %d\r\n", error);
        }

#if MBED_CONF_APP_FILESYSTEM_SUPPORT
        /* Enable privacy so we can find the keys */
        error = _ble.gap().enablePrivacy(true);

        if (error) {
            printf("Error enabling privacy\r\n");
        }

        Gap::peripheral_privacy_configuration_t configuration_p = {
            /* use_non_resolvable_random_address */ false,
            Gap::peripheral_privacy_configuration_t::REJECT_NON_RESOLVED_ADDRESS
        };
        _ble.gap().setPeripheralPrivacyConfiguration(&configuration_p);

        Gap::central_privay_configuration_t configuration_c = {
            /* use_non_resolvable_random_address */ false,
            Gap::CentralPrivacyConfiguration_t::RESOLVE_AND_FORWARD
        };
        _ble.gap().setCentralPrivacyConfiguration(&configuration_c);

        /* this demo switches between being master and slave */
        _ble.securityManager().setHintFutureRoleReversal(true);
#endif

        /* Tell the security manager to use methods in this class to inform us
         * of any events. Class needs to implement SecurityManagerEventHandler. */
        _ble.securityManager().setSecurityManagerEventHandler(this);

        /* gap events also handled by this class */
        _ble.gap().setEventHandler(this);

        /* print device address */
        print_mac_address();

        /* start test in 500 ms */
        _event_queue.call_in(500, this, &SMDevice::start);
    };

    /** Schedule processing of events from the BLE in the event queue. */
    void schedule_ble_events(BLE::OnEventsToProcessCallbackContext *context)
    {
        _event_queue.call(mbed::callback(&context->ble, &BLE::processEvents));
    };

    /** Blink LED to show we're running */
    void blink(void)
    {
        _led1 = !_led1;
    };

private:
    /* Event handler */

    /** Respond to a pairing request. This will be called by the stack
     * when a pairing request arrives and expects the application to
     * call acceptPairingRequest or cancelPairingRequest */
    virtual void pairingRequest(
        ble::connection_handle_t connectionHandle
    ) {
        printf("Pairing requested - authorising\r\n");
        _ble.securityManager().acceptPairingRequest(connectionHandle);
    }

    /** Inform the application of a successful pairing. Terminate the demonstration. */
    virtual void pairingResult(
        ble::connection_handle_t connectionHandle,
        SecurityManager::SecurityCompletionStatus_t result
    ) {
        if (result == SecurityManager::SEC_STATUS_SUCCESS) {
            printf("Pairing successful\r\n");
        } else {
            printf("Pairing failed\r\n");
        }
    }

		
    /**
     * Helper to construct an event handler from a member function of this
     * instance.
     */
    template<typename ContextType>
    FunctionPointerWithContext<ContextType> as_cb(
        void (SMDevice::*member)(ContextType context)
    ) {
        return makeFunctionPointer(this, member);
    }

    /** Inform the application of change in encryption status. This will be
     * communicated through the serial port */
    virtual void linkEncryptionResult(
        ble::connection_handle_t connectionHandle,
        ble::link_encryption_t result
    ) {
        if (result == ble::link_encryption_t::ENCRYPTED) {
            printf("Link ENCRYPTED\r\n");
        } else if (result == ble::link_encryption_t::ENCRYPTED_WITH_MITM) {
            printf("Link ENCRYPTED_WITH_MITM\r\n");
        } else if (result == ble::link_encryption_t::NOT_ENCRYPTED) {
            printf("Link NOT_ENCRYPTED\r\n");
        }

				_connectionHandle = connectionHandle;
				ble_error_t error = _ble.gattClient().launchServiceDiscovery(
            connectionHandle,
            as_cb(&SMDevice::when_service_discovered),
            as_cb(&SMDevice::when_characteristic_discovered)
        );
				
        if (error) {
            printf("Error %u returned by _client->launchServiceDiscovery.\r\n", error);
            return;
        }

        /* disconnect in 2 s *///50seconds
        _event_queue.call_in(
            50000,
            &_ble.gap(),
            disconnect_call,
            _handle,
            ble::local_disconnection_reason_t(ble::local_disconnection_reason_t::USER_TERMINATION)
        );
    }

    /** This is called by Gap to notify the application we disconnected,
     *  in our case it ends the demonstration. */
    virtual void onDisconnectionComplete(const ble::DisconnectionCompleteEvent &)
    {
        printf("Disconnected\r\n");
        _event_queue.break_dispatch();
    };
		
		////////////
		   static void print_uuid(const UUID &uuid)
    {
        const uint8_t *uuid_value = uuid.getBaseUUID();

        // UUIDs are in little endian, print them in big endian
        for (size_t i = 0; i < uuid.getLen(); ++i) {
            printf("%02X", uuid_value[(uuid.getLen() - 1) - i]);
        }
    }

    typedef DiscoveredCharacteristic::Properties_t Properties_t;
		
    /**
     * Print the value of a characteristic properties.
     */
    static void print_properties(const Properties_t &properties)
    {
        const struct {
            bool (Properties_t::*fn)() const;
            const char* str;
        } prop_to_str[] = {
            { &Properties_t::broadcast, "broadcast" },
            { &Properties_t::read, "read" },
            { &Properties_t::writeWoResp, "writeWoResp" },
            { &Properties_t::write, "write" },
            { &Properties_t::notify, "notify" },
            { &Properties_t::indicate, "indicate" },
            { &Properties_t::authSignedWrite, "authSignedWrite" }
        };

        printf("[");
        for (size_t i = 0; i < (sizeof(prop_to_str) / sizeof(prop_to_str[0])); ++i) {
            if ((properties.*(prop_to_str[i].fn))()) {
                printf(" %s", prop_to_str[i].str);
            }
        }
        printf(" ]");
    }
		
		
		////////
		
		
		void when_service_discovered(const DiscoveredService *discovered_service)
    {
        // print information of the service discovered
        printf("Service discovered: value = ");
        print_uuid(discovered_service->getUUID());
        printf(", start = %u, end = %u.\r\n",
            discovered_service->getStartHandle(),
            discovered_service->getEndHandle()
        );
    }
		
		void when_characteristic_discovered(const DiscoveredCharacteristic *discovered_characteristic)
    {
        // print characteristics properties
        printf("\tCharacteristic discovered: uuid = ");
        print_uuid(discovered_characteristic->getUUID());
        printf(", properties = ");
        print_properties(discovered_characteristic->getProperties());
        printf(
            ", decl handle = %u, value handle = %u, last handle = %u.\r\n",
            discovered_characteristic->getDeclHandle(),
            discovered_characteristic->getValueHandle(),
            discovered_characteristic->getLastHandle()
        );
			  
			
			/*char uuidStr[128];
			memset(&uuidStr[0], 0, 128);
		const UUID &uuid = discovered_characteristic->getUUID();
			const uint8_t *uuid_value = uuid.getBaseUUID();

        // UUIDs are in little endian, print them in big endian
        for (size_t i = 0; i < uuid.getLen(); ++i) {
					sprintf(&uuidStr[i * 2], "%02X", uuid_value[(uuid.getLen() - 1) - i]);
        }
				
				printf("** Our uuid %s", uuidStr);*/
			if (discovered_characteristic->getDeclHandle() == 28 && !_found_characteristic) {
				printf("Match found");
				_found_characteristic = true;
				_discoveredCharacteristic = *discovered_characteristic;
//				BLE &ble = BLE::Instance();
//				ble.gattClient().onServiceDiscoveryTermination(as_cb(&SMDevice::whenServiceDiscoveryTerminated));
				//5sec delay
				_event_queue.call_in(
            5000,
						this,
						&SMDevice::whenServiceDiscoveryTerminated
        );
			}
    } 
		
		void whenServiceDiscoveryTerminated() {
			if (!_found_characteristic) return;
			printf(" Discovery Termination:In \n");
			print_uuid(_discoveredCharacteristic.getUUID());
        printf(", properties = ");
        print_properties(_discoveredCharacteristic.getProperties());
			BLE &ble = BLE::Instance();
			ble_error_t err = ble.gattClient().discoverCharacteristicDescriptors( 
					_discoveredCharacteristic, 
					as_cb(&SMDevice::whenDescriptorDiscovered),
					as_cb(&SMDevice::whenDiscoveryEnd)
			);

			if (err) { 
				 printf("discoverCharacteristicDescriptors call failed with Ble error: %d" , err);
			}
			printf(" Discovery Termination:out \n");
		}
		 
		void onUpdatesCallback(const GattHVXCallbackParams *params)
			{
				printf("onUpdatesCallback : update received: handle %u, length %u, type = %d \r\n", params->handle,params->len,params->type);
				if (params->handle == _discoveredCharacteristic.getValueHandle()) {
					printf("Packet size %d \n", (uint8_t)params->data[0]);
					printf("Spo2 %d \n", (uint8_t)params->data[7]);
					printf("Pulse %d \n", (uint16_t)((params->data[8] << 8) | params->data[9]));
				}
			}
		
		void whenDescriptorDiscovered(const CharacteristicDescriptorDiscovery::DiscoveryCallbackParams_t* p) { 
						BLE &ble = BLE::Instance();
						printf("whenDescriptorDiscovered:In \n");
				printf("\tCharacteristic DESCRIPTOR discovered: uuid = ");
        print_uuid(p->characteristic.getUUID());
        printf(", properties = ");
        print_properties(p->characteristic.getProperties());
            if (p->descriptor.getUUID() == BLE_UUID_DESCRIPTOR_CLIENT_CHAR_CONFIG) { 
							print_uuid(p->descriptor.getUUID());
								printf("whenDescriptorDiscovered - p->descriptor.getUUID():In \n");
                _CCCD = p->descriptor.getAttributeHandle();
                ble.gattClient().terminateCharacteristicDescriptorDiscovery(_discoveredCharacteristic);
            }
					printf(" whenDescriptorDiscovered:Out \n");
        }
    
        void whenDiscoveryEnd(const CharacteristicDescriptorDiscovery::TerminationCallbackParams_t* p) {
						printf(" whenDiscoveryEnd:In \n");
            if (p->status) {
								return;
            }
						printf(" whenDiscoveryEnd:Out1 \n"); 
            BLE &ble = BLE::Instance();
						// otherwise launch write the descriptor
            // first register the write callback 
					
						printf(" whenDiscoveryEnd:after launch descriptor \n"); 
            uint16_t cccd_value = BLE_HVX_NOTIFICATION;
						ble_error_t err = ble.gattClient().write( 
                GattClient::GATT_OP_WRITE_REQ,
                _discoveredCharacteristic.getConnectionHandle(),
                _CCCD,
                sizeof(cccd_value),
                (uint8_t*) &cccd_value
            );
						    ble.gattClient().onHVX(
                as_cb(&SMDevice::onUpdatesCallback)
            );
						printf(" whenDiscoveryEnd:after writing notification \n"); 
            if (err) { 
                
                // remove the callback registered for data write 
                ble.gattClient().onDataWritten().detach(
                    as_cb(&SMDevice::whenDataWritten)
                );
                return;
            }
						printf(" whenDiscoveryEnd:OutFinal \n");
        }

			virtual void whenDataWritten(const GattWriteCallbackParams* params) {
					printf("whenDataWritten ");
					//printf("Spo2 %d ", (uint8_t)params->data[7]);
					//printf("Pulse %d ", (uint16_t)((params->data[8] << 8) | params->data[9]));
			}
				
		virtual void on_attribute_read(const GattReadCallbackParams* params) {
			printf("Read attribute ");
			//printf("Spo2 %d", (uint8_t)params->data[7]);
			//printf("Pulse %d", (uint16_t)((params->data[8] << 8) | params->data[9]));
		}

    virtual void onAdvertisingEnd(const ble::AdvertisingEndEvent &event)
    {
        if (!event.isConnected()) {
            printf("Advertising timed out - aborting\r\n");
            _event_queue.break_dispatch();
        }
    }

    virtual void onScanTimeout(const ble::ScanTimeoutEvent &)
    {
        printf("Scan timed out - aborting\r\n");
        _event_queue.break_dispatch();
    }

private:
		DiscoveredCharacteristic _discoveredCharacteristic;
		bool _found_characteristic;
    DigitalOut _led1;

protected:
    BLE &_ble;
    events::EventQueue &_event_queue;
    ble::address_t &_peer_address;
    ble::connection_handle_t _handle;
    bool _is_connecting;
};

/** A peripheral device will advertise, accept the connection and request
 * a change in link security. */
class SMDevicePeripheral : public SMDevice {
public:
    SMDevicePeripheral(BLE &ble, events::EventQueue &event_queue, ble::address_t &peer_address)
        : SMDevice(ble, event_queue, peer_address) { }

    virtual void start()
    {
        /* Set up and start advertising */
        uint8_t adv_buffer[ble::LEGACY_ADVERTISING_MAX_SIZE];
        /* use the helper to build the payload */
        ble::AdvertisingDataBuilder adv_data_builder(
            adv_buffer
        );

        adv_data_builder.setFlags();
        adv_data_builder.setName(DEVICE_NAME);

        /* Set payload for the set */
        ble_error_t error = _ble.gap().setAdvertisingPayload(
            ble::LEGACY_ADVERTISING_HANDLE,
            adv_data_builder.getAdvertisingData()
        );

        if (error) {
            print_error(error, "Gap::setAdvertisingPayload() failed");
            _event_queue.break_dispatch();
            return;
        }

        ble::AdvertisingParameters adv_parameters(
            ble::advertising_type_t::CONNECTABLE_UNDIRECTED
        );

        error = _ble.gap().setAdvertisingParameters(
            ble::LEGACY_ADVERTISING_HANDLE,
            adv_parameters
        );

        if (error) {
            print_error(error, "Gap::setAdvertisingParameters() failed");
            return;
        }

        error = _ble.gap().startAdvertising(ble::LEGACY_ADVERTISING_HANDLE);

        if (error) {
            print_error(error, "Gap::startAdvertising() failed");
            return;
        }

        printf("Please connect to device\r\n");

        /** This tells the stack to generate a pairingRequest event
         * which will require this application to respond before pairing
         * can proceed. Setting it to false will automatically accept
         * pairing. */
        _ble.securityManager().setPairingRequestAuthorisation(true);
    };

    /** This is called by Gap to notify the application we connected,
     *  in our case it immediately requests a change in link security */
    virtual void onConnectionComplete(const ble::ConnectionCompleteEvent &event)
    {
        ble_error_t error;

        /* remember the device that connects to us now so we can connect to it
         * during the next demonstration */
        _peer_address = event.getPeerAddress();

        printf("Connected to peer: ");
        print_address(event.getPeerAddress().data());

        _handle = event.getConnectionHandle();

        /* Request a change in link security. This will be done
         * indirectly by asking the master of the connection to
         * change it. Depending on circumstances different actions
         * may be taken by the master which will trigger events
         * which the applications should deal with. */
        error = _ble.securityManager().setLinkSecurity(
            _handle,
            SecurityManager::SECURITY_MODE_ENCRYPTION_NO_MITM
        );

        if (error) {
            printf("Error during SM::setLinkSecurity %d\r\n", error);
            return;
        }
    };
};

/** A central device will scan, connect to a peer and request pairing. */
class SMDeviceCentral : public SMDevice {
public:
    SMDeviceCentral(BLE &ble, events::EventQueue &event_queue, ble::address_t &peer_address)
        : SMDevice(ble, event_queue, peer_address) { }

    virtual void start()
    {
        ble::ScanParameters params;
        ble_error_t error = _ble.gap().setScanParameters(params);

        if (error) {
            print_error(error, "Error in Gap::startScan %d\r\n");
            return;
        }

        /* start scanning, results will be handled by onAdvertisingReport */
        error = _ble.gap().startScan();

        if (error) {
            print_error(error, "Error in Gap::startScan %d\r\n");
            return;
        }

        printf("Please advertise\r\n");
				//_peer_address_nonin = 00:0d:6F:10:45:99 ;
        printf("Scanning for: ");
        print_address(_peer_address.data());
				
				//printf("Nonin address ---> 00:0d:6f:10:45:99");
				//get_nonin_address(_peer_address_nonin.data());
				
    }

private:
    /* Gap::EventHandler */

    /** Look at scan payload to find a peer device and connect to it */
    virtual void onAdvertisingReport(const ble::AdvertisingReportEvent &event)
    {
        /* don't bother with analysing scan result if we're already connecting */
        if (_is_connecting) {
            return;
        }

        /* parse the advertising payload, looking for a discoverable device */
        if (event.getPeerAddress() == _peer_address) {
            ble_error_t error = _ble.gap().stopScan();

            if (error) {
                print_error(error, "Error caused by Gap::stopScan");
                return;
            }

            ble::ConnectionParameters connection_params(
                ble::phy_t::LE_1M,
                ble::scan_interval_t(50),
                ble::scan_window_t(50),
                ble::conn_interval_t(50),
                ble::conn_interval_t(100),
                ble::slave_latency_t(0),
                ble::supervision_timeout_t(100)
            );
            connection_params.setOwnAddressType(ble::own_address_type_t::RANDOM);

            error = _ble.gap().connect(
                event.getPeerAddressType(),
                event.getPeerAddress(),
                connection_params
            );

            if (error) {
                print_error(error, "Error caused by Gap::connect");
                return;
            }

            /* we may have already scan events waiting
             * to be processed so we need to remember
             * that we are already connecting and ignore them */
            _is_connecting = true;

            return;
        }
    }

    /** This is called by Gap to notify the application we connected,
     *  in our case it immediately request pairing */
    virtual void onConnectionComplete(const ble::ConnectionCompleteEvent &event)
    {
        if (event.getStatus() == BLE_ERROR_NONE) {
            /* store the handle for future Security Manager requests */
            _handle = event.getConnectionHandle();

            printf("Connected\r\n");

            /* in this example the local device is the master so we request pairing */
            ble_error_t error = _ble.securityManager().requestPairing(_handle);

             if (error) {
                 printf("Error during SM::requestPairing %d\r\n", error);
                 return;
             }

            /* upon pairing success the application will disconnect */
        }

        /* failed to connect - restart scan */
        ble_error_t error = _ble.gap().startScan();

        if (error) {
            print_error(error, "Error in Gap::startScan %d\r\n");
            return;
        }
    };
};


#if MBED_CONF_APP_FILESYSTEM_SUPPORT
bool create_filesystem()
{
    static LittleFileSystem fs("fs");

    /* replace this with any physical block device your board supports (like an SD card) */
    static HeapBlockDevice bd(4096, 256);

    int err = bd.init();

    if (err) {
        return false;
    }

    err = bd.erase(0, bd.size());

    if (err) {
        return false;
    }

    err = fs.mount(&bd);

    if (err) {
        /* Reformat if we can't mount the filesystem */
        printf("No filesystem found, formatting...\r\n");

        err = fs.reformat(&bd);

        if (err) {
            return false;
        }
    }

    return true;
}
#endif //MBED_CONF_APP_FILESYSTEM_SUPPORT

int main()
{
    BLE& ble = BLE::Instance();
    events::EventQueue queue;

#if MBED_CONF_APP_FILESYSTEM_SUPPORT
    /* if filesystem creation fails or there is no filesystem the security manager
     * will fallback to storing the security database in memory */
    if (!create_filesystem()) {
        printf("Filesystem creation failed, will use memory storage\r\n");
    }
#endif

    while(1) {
//        {
//            printf("\r\n PERIPHERAL \r\n\r\n");
//            SMDevicePeripheral peripheral(ble, queue, peer_address);
//            peripheral.run();
//        }

        {
            printf("\r\n CENTRAL \r\n\r\n");
            SMDeviceCentral central(ble, queue, peer_address);
            central.run();
        }
    }

    return 0;
}
