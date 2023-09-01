package dns

func boolToUint(b bool) uint {
	if b {
			return 1
	}
	return 0
}