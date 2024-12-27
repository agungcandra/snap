package codes

type ErrorResponseCode struct {
	Status      int
	ServiceCode int
	CaseCode    int
}

func (code ErrorResponseCode) Error() string {
	return ""
}
