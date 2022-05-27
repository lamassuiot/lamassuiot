package cas

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"math"
	"math/big"
	"os"
	"strconv"
	"time"

	"github.com/globalsign/pemfile"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/jakehl/goid"
	lamassuCAClient "github.com/lamassuiot/lamassuiot/pkg/ca/client"

	caDTO "github.com/lamassuiot/lamassuiot/pkg/ca/common/dto"
	"github.com/lamassuiot/lamassuiot/test/e2e/utils"
	client "github.com/lamassuiot/lamassuiot/test/e2e/utils/clients"
)

func ManageCAs(caNumber int, scaleIndex int, certPath string, domain string) (caDTO.Cert, error) {
	var logger log.Logger
	logger = log.NewJSONLogger(os.Stdout)
	logger = level.NewFilter(logger, level.AllowDebug())
	logger = log.With(logger, "ts", log.DefaultTimestampUTC)
	logger = log.With(logger, "caller", log.DefaultCaller)
	var f, err = os.Create("./test/e2e/manage-cas/GetCAs_" + strconv.Itoa(scaleIndex) + ".csv")
	if err != nil {
		return caDTO.Cert{}, err
	}
	caClient, err := client.LamassuCaClient(certPath, domain)
	if err != nil {
		return caDTO.Cert{}, err
	}
	var createCa []caDTO.Cert
	for i := 0; i < caNumber; i++ {
		caName := goid.NewV4UUID().String()

		_, err = caClient.CreateCA(context.Background(), caDTO.Pki, caName, caDTO.PrivateKeyMetadata{KeyType: "rsa", KeyBits: 2048}, caDTO.Subject{CommonName: caName}, 365*time.Hour, 30*time.Hour)
		if err != nil {
			level.Error(logger).Log("err", err)
			return caDTO.Cert{}, err
		}
		createCa, err = LatencyGetCAs(caClient, f, logger)
		if err != nil {
			return caDTO.Cert{}, err
		}

	}
	err = caClient.DeleteCA(context.Background(), caDTO.Pki, createCa[caNumber-1].Name)
	if err != nil {
		return caDTO.Cert{}, err
	}
	err = CreateCertKey()
	if err != nil {
		level.Error(logger).Log("err", err)
		return caDTO.Cert{}, err
	}
	certContent, err := ioutil.ReadFile("./test/e2e/manage-cas/ca.crt")
	if err != nil {
		level.Error(logger).Log("err", err)
		return caDTO.Cert{}, err
	}
	cpb, _ := pem.Decode(certContent)

	importcrt, err := x509.ParseCertificate(cpb.Bytes)
	if err != nil {
		level.Error(logger).Log("err", err)
		return caDTO.Cert{}, err
	}
	privateKey, err := pemfile.ReadPrivateKey("./test/e2e/manage-cas/ca.key")
	if err != nil {
		level.Error(logger).Log("err", err)
		return caDTO.Cert{}, err
	}
	ca, err := caClient.ImportCA(context.Background(), caDTO.Pki, importcrt.Subject.CommonName, *importcrt, caDTO.PrivateKey{KeyType: caDTO.RSA, Key: privateKey}, 30*time.Hour)
	if err != nil {
		level.Error(logger).Log("err", err)
		return caDTO.Cert{}, err
	}
	f.Close()
	return ca, nil
}

func LatencyGetCAs(caClient lamassuCAClient.LamassuCaClient, f *os.File, logger log.Logger) ([]caDTO.Cert, error) {
	var max, min float64
	max = 0
	min = 12
	var createCa []caDTO.Cert
	for k := 0; k < 10; k++ {
		before := time.Now().UnixNano()
		cas, err := caClient.GetCAs(context.Background(), caDTO.Pki)
		if err != nil {
			level.Error(logger).Log("err", err)
			return []caDTO.Cert{}, err
		}
		after := time.Now().UnixNano()
		latency := float64((after - before)) / 1000000000
		max = math.Max(max, latency)
		min = math.Min(min, latency)
		createCa = cas
	}
	media := (max + min) / 2
	err := utils.WriteDataFile(strconv.Itoa(len(createCa)), max, min, media, f)
	if err != nil {
		level.Error(logger).Log("err", err)
		return []caDTO.Cert{}, err
	}

	return createCa, nil
}
func CreateCertKey() error {
	serialnumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 160))
	if err != nil {
		return err
	}
	ca := &x509.Certificate{
		SerialNumber: serialnumber,
		Subject: pkix.Name{
			Organization:       []string{"IKL"},
			Country:            []string{"ES"},
			Province:           []string{"Gipuzkoa"},
			Locality:           []string{"Arrasate"},
			OrganizationalUnit: []string{"ZPD"},
			CommonName:         goid.NewV4UUID().String(),
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return err
	}
	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	ioutil.WriteFile("./test/e2e/manage-cas/ca.crt", caPEM.Bytes(), 0777)

	caPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	})
	ioutil.WriteFile("./test/e2e/manage-cas/ca.key", caPrivKeyPEM.Bytes(), 0777)
	return nil
}
