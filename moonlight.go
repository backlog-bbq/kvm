package kvm

import (
	"fmt"
	"net"

	"github.com/jetkvm/kvm/internal/moonlight"
)

var moonlightServer *moonlight.Server

// initMoonlight creates and starts the Moonlight streaming server if it is enabled
// in the device configuration.
func initMoonlight() {
	if !config.MoonlightEnabled {
		logger.Info().Msg("Moonlight server disabled (MoonlightEnabled=false)")
		return
	}

	hostname := GetDefaultHostname()
	if networkManager != nil {
		if h := networkManager.Hostname(); h != "" {
			hostname = h
		}
	}

	mac := getMACAddress()

	srv, err := moonlight.NewServer(moonlight.ServerConfig{
		DeviceID: GetDeviceID(),
		Hostname: hostname,
		MacAddr:  mac,
		HID: moonlight.HIDCallbacks{
			RelMouseMove: func(dx, dy int8, buttons uint8) error {
				return rpcRelMouseReport(dx, dy, buttons)
			},
			AbsMouseMove: func(x, y int, buttons uint8) error {
				return rpcAbsMouseReport(x, y, buttons)
			},
			Keyboard: func(key byte, press bool) error {
				return rpcKeypressReport(key, press)
			},
			KeyboardFull: func(modifier byte, keys []byte) error {
				return rpcKeyboardReport(modifier, keys)
			},
			Scroll: func(dy int8) error {
				return rpcWheelReport(dy)
			},
		},
		PINCallback: func(deviceName, uniqueID string) {
			// Emit a JSON-RPC event so the web UI can prompt the user to type
			// the PIN that is displayed on their Moonlight client.
			writeJSONRPCEvent("moonlightPairingRequest", map[string]string{
				"deviceName": deviceName,
				"uniqueID":   uniqueID,
			}, currentSession)
			logger.Info().
				Str("deviceName", deviceName).
				Str("uniqueID", uniqueID).
				Msg("Moonlight pairing requested: waiting for user to enter PIN from client")
		},
	})
	if err != nil {
		logger.Error().Err(err).Msg("failed to create Moonlight server")
		return
	}

	if err := srv.Start(); err != nil {
		logger.Error().Err(err).Msg("failed to start Moonlight server")
		return
	}

	moonlightServer = srv
	logger.Info().Msg("Moonlight server initialised")
}

// rpcSubmitMoonlightPIN is called by the web UI when the user has typed the
// PIN shown on their Moonlight client. It forwards the PIN to the pending
// pairing handshake so that the AES session key can be derived and the
// challenge-response can continue.
func rpcSubmitMoonlightPIN(uniqueID, pin string) error {
	if moonlightServer == nil {
		return fmt.Errorf("Moonlight server is not running")
	}
	return moonlightServer.SubmitPIN(uniqueID, pin)
}

// getMACAddress returns the MAC address of the primary network interface (eth0)
// formatted as XX:XX:XX:XX:XX:XX, or a placeholder if unavailable.
func getMACAddress() string {
	iface, err := net.InterfaceByName("eth0")
	if err != nil || len(iface.HardwareAddr) == 0 {
		return "00:00:00:00:00:00"
	}
	return iface.HardwareAddr.String()
}
