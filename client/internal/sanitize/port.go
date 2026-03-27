package sanitize

import "strconv"

func Port(portStr string) (int, error) {
	// parse port number
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0, err
	}

	if port < 1 || port > 65535 {
		return 0, strconv.ErrRange
	}

	return port, nil
}
