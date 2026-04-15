package sanitize

func OptInstanceId(instanceId string) (*string, error) {
	if instanceId == "" {
		return nil, nil
	}

	return &instanceId, nil
}
