package timestamp

import (
	"bytes"
	"encoding/pem"
	"fmt"
	"go-ca/util"
	"io"
	"net/http"
	"os"
	"time"

	ts "github.com/digitorus/timestamp"
	"github.com/spf13/cobra"
)

var TimestampCmd = &cobra.Command{
	Version: util.Version,
	Use:     "timestamp",
	Short:   "Generate RFC3161 timestamp",
	Long: `Generate RFC3161 timestamp

	Timestamp with TSA cert written to file path
	./go-ca pki timestamp --digest_algo=384 --tsa_server_url=https://freetsa.org/tsr --input_file_path=/home/bilal/data/file.dat
		--token_out_path=/home/bilal/data/token.der --tsa_cert_out_path=/home/bilal/data/tsa.pem

	Timestamp by TSA policy ID
	./go-ca pki timestamp --digest_algo=384 --tsa_server_url=https://freetsa.org/tsr --input_file_path=/home/bilal/data/file.dat tsa_policy_id=<POLICY_OID>
		--token_out_path=/home/bilal/data/token.der

	Timestamp by providing username and password for TSA that requires authentication
	./go-ca pki timestamp --digest_algo=384 --tsa_server_url=https://freetsa.org/tsr --input_file_path=/home/bilal/data/file.dat -username=<USERNAME>
		--password=<PASSWORD> --token_out_path=/home/bilal/data/token.der

	`,
	Run: func(cmd *cobra.Command, args []string) {
		tsaReqBytes, err := generateTSARequest()
		if err != nil {
			fmt.Println(fmt.Errorf("%w", err))
			return
		}
		tsaResBytes, err := sendTSPRequest(tsaReqBytes)
		if err != nil {
			fmt.Println(fmt.Errorf("%w", err))
			return
		}
		timestampRes, err := ts.ParseResponse(tsaResBytes)
		if err != nil {
			fmt.Println(fmt.Errorf("%w", err))
			return
		}
		err = os.WriteFile(tsParams.tokenOutPath, timestampRes.RawToken, 0644)
		if err != nil {
			fmt.Println(fmt.Errorf("%w", err))
			return
		}
		fmt.Println("Timestamp token file path: " + tsParams.tokenOutPath)
		if len(tsParams.tsaCertOutPath) != 0 {
			tsaCertPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: timestampRes.Certificates[0].Raw,
			})
			err = os.WriteFile(tsParams.tsaCertOutPath, tsaCertPEM, 0644)
			if err != nil {
				fmt.Println(fmt.Errorf("%w", err))
				return
			}
			fmt.Println("TSA cert file path: " + tsParams.tokenOutPath)
		}
		fmt.Println("Timestamp time: " + timestampRes.Time.String())
		fmt.Println("TSA certificate chain: ")
		for _, cert := range timestampRes.Certificates {
			fmt.Println(cert.Subject.ToRDNSequence().String())
		}
	},
}

func generateTSARequest() ([]byte, error) {
	toBeTsData, err := os.ReadFile(tsParams.inputFilePath)
	if err != nil {
		return nil, fmt.Errorf("unable to read input data to be timestamped: %w", err)
	}
	cryptoHash, hashedMessage, err := util.GetMessageDigest(tsParams.digestAlgo, toBeTsData)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	nonce, err := util.GenerateRandomNumber(5)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	tsaReq := ts.Request{
		HashAlgorithm: cryptoHash,
		HashedMessage: hashedMessage,
		Nonce:         nonce,
		Certificates:  true,
	}
	if len(tsParams.tsaPolicyOID) != 0 {
		tasPolicyID, err := util.ConvertStringOIDToASN1OID(tsParams.tsaPolicyOID)
		if err != nil {
			return nil, fmt.Errorf("%w", err)
		}
		tsaReq.TSAPolicyOID = tasPolicyID
	}
	tsaReqBytes, err := tsaReq.Marshal()
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	return tsaReqBytes, nil
}

func sendTSPRequest(tsaRequest []byte) ([]byte, error) {
	req, err := http.NewRequest(http.MethodPost, tsParams.tsaServerURL, bytes.NewBuffer(tsaRequest))
	if err != nil {
		return nil, fmt.Errorf("unable to create HTTP POST request: %w", err)

	}
	req.Header.Set("Content-Type", "application/timestamp-query")
	if len(tsParams.tsaUserName) != 0 && len(tsParams.tsaPassword) != 0 {
		req.SetBasicAuth(tsParams.tsaUserName, tsParams.tsaPassword)
	}
	client := http.Client{
		Timeout: 30 * time.Second,
	}
	tsaRes, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making HTTP POST request: %w", err)
	}
	defer tsaRes.Body.Close()

	if tsaRes.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error: %s", tsaRes.Status)

	}
	if tsaRes.Header.Get("Content-Type") != "application/timestamp-reply" {
		return nil, fmt.Errorf("invalid HTTP response content type header: %s", tsaRes.Header.Get("Content-Type"))
	}
	body, err := io.ReadAll(tsaRes.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response: %w", err)
	}
	return body, nil
}

func init() {
	TimestampCmd.Flags().SortFlags = false

	tsParams.addTimestampParams(TimestampCmd)
}
