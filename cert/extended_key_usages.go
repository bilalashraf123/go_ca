package cert

import "encoding/asn1"

var (
	extendedKeyUsages = map[string]asn1.ObjectIdentifier{
		"Any":                            {2, 5, 29, 37, 0},
		"ServerAuth":                     {1, 3, 6, 1, 5, 5, 7, 3, 1},
		"ClientAuth":                     {1, 3, 6, 1, 5, 5, 7, 3, 2},
		"CodeSigning":                    {1, 3, 6, 1, 5, 5, 7, 3, 3},
		"EmailProtection":                {1, 3, 6, 1, 5, 5, 7, 3, 4},
		"IPSECEndSystem":                 {1, 3, 6, 1, 5, 5, 7, 3, 5},
		"IPSECTunnel":                    {1, 3, 6, 1, 5, 5, 7, 3, 6},
		"IPSECUser":                      {1, 3, 6, 1, 5, 5, 7, 3, 7},
		"TimeStamping":                   {1, 3, 6, 1, 5, 5, 7, 3, 8},
		"OCSPSigning":                    {1, 3, 6, 1, 5, 5, 7, 3, 9},
		"MicrosoftServerGatedCrypto":     {1, 3, 6, 1, 4, 1, 311, 10, 3, 3},
		"NetscapeServerGatedCrypto":      {2, 16, 840, 1, 113730, 4, 1},
		"MicrosoftCommercialCodeSigning": {1, 3, 6, 1, 4, 1, 311, 2, 1, 22},
		"MicrosoftKernelCodeSigning":     {1, 3, 6, 1, 4, 1, 311, 61, 1, 1},
	}
)
