package cert

type KeyUsage string

const (
	DigitalSignature KeyUsage = "digitalSignature"
	NonRepudiation   KeyUsage = "nonRepudiation"
	KeyEncipherment  KeyUsage = "keyEncipherment"
	DataEncipherment KeyUsage = "dataEncipherment"
	KeyAgreement     KeyUsage = "keyAgreement"
	KeyCertSign      KeyUsage = "keyCertSign"
	CRLSign          KeyUsage = "cRLSign"
	EncipherOnly     KeyUsage = "encipherOnly"
	DecipherOnly     KeyUsage = "decipherOnly"
)
