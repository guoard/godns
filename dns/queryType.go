package dns

type QueryType uint16

const (
	UNKNOWN QueryType = iota
	A
	NS
	CNAME
	MX
	AAAA
)

func QueryTypeFromNum(num uint16) QueryType {
	switch num {
	case 1:
		return A
	case 2:
		return NS
	case 5:
		return CNAME
	case 15:
		return MX
	case 28:
		return AAAA
	default:
		return UNKNOWN
	}
}

func (qt QueryType) ToNum() uint16 {
	switch qt {
	case A:
		return 1
	case NS:
		return 2
	case CNAME:
		return 5
	case MX:
		return 15
	case AAAA:
		return 28
	default: // unknown
		return 0
	}
}
