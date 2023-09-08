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

var queryTypeMapping = map[uint16]QueryType{
	1:  A,
	2:  NS,
	5:  CNAME,
	15: MX,
	28: AAAA,
}

func QueryTypeFromNum(num uint16) QueryType {
	qt, found := queryTypeMapping[num]
	if found {
		return qt
	}
	return UNKNOWN
}

func (qt QueryType) ToNum() uint16 {
	for num, queryType := range queryTypeMapping {
		if qt == queryType {
			return num
		}
	}
	return 0
}
