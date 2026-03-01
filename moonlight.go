package kvm

import (
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
		PINCallback: func(pin string) {
			// Emit a JSON-RPC event so the web UI can display the pairing PIN.
			writeJSONRPCEvent("moonlightPairingPin", map[string]string{"pin": pin}, currentSession)
			logger.Info().Str("pin", pin).Msg("Moonlight pairing PIN (display to user)")
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

// getMACAddress returns the MAC address of the primary network interface (eth0)
// formatted as XX:XX:XX:XX:XX:XX, or a placeholder if unavailable.
func getMACAddress() string {
	iface, err := net.InterfaceByName("eth0")
	if err != nil || len(iface.HardwareAddr) == 0 {
		return "00:00:00:00:00:00"
	}
	return iface.HardwareAddr.String()
}
