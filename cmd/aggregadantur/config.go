package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/orange-cloudfoundry/aggregadantur/models"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
	"os"
)

type Log struct {
	Level   string `yaml:"level"`
	NoColor bool   `yaml:"no_color"`
	InJson  bool   `yaml:"in_json"`
}

func (c *Log) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain Log
	err := unmarshal((*plain)(c))
	if err != nil {
		return err
	}
	log.SetFormatter(&log.TextFormatter{
		DisableColors: c.NoColor,
	})
	if c.Level != "" {
		lvl, err := log.ParseLevel(c.Level)
		if err != nil {
			return err
		}
		log.SetLevel(lvl)
	}
	if c.InJson {
		log.SetFormatter(&log.JSONFormatter{})
	}

	return nil
}

type Server struct {
	Listen     string `yaml:"listen"`
	EnableSSL  bool   `yaml:"enable_ssl"`
	TLSPem     TLSPem `yaml:"tls_pem"`
	SessionKey string `yaml:"session_key"`
}

type Config struct {
	Server  Server                   `yaml:"server"`
	Logging Log                      `yaml:"logging"`
	Routes  []*models.AggregateRoute `yaml:"routes"`
}

func (c *Config) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain Config
	err := unmarshal((*plain)(c))
	if err != nil {
		return err
	}

	if c.Server.Listen == "" {
		port := os.Getenv("PORT")
		if port == "" {
			return fmt.Errorf("Server listen address must be set")
		}
		c.Server.Listen = ":" + port
	}
	if c.Server.SessionKey == "" {
		return fmt.Errorf("Server session key must be set")
	}

	return nil
}

func GetConfig(configPath string) (Config, error) {
	b, err := os.ReadFile(configPath)
	if err != nil {
		return Config{}, err
	}
	config := Config{}
	err = yaml.Unmarshal(b, &config)
	if err != nil {
		return Config{}, err
	}

	return config, nil
}

type TLSPem struct {
	CertChain  string `json:"cert_chain" yaml:"cert_chain" cloud:"cert_chain"`
	PrivateKey string `json:"private_key" yaml:"private_key" cloud:"private_key"`
	CA         string `json:"ca" yaml:"ca" cloud:"ca"`
}

func (x *TLSPem) CertificateAndPool() (tls.Certificate, *x509.CertPool, error) {
	certificate, err := tls.X509KeyPair([]byte(x.CertChain), []byte(x.PrivateKey))
	if err != nil {
		errMsg := fmt.Sprintf("Error loading key pair: %s", err.Error())
		return tls.Certificate{}, nil, fmt.Errorf(errMsg)
	}
	certPool, err := x509.SystemCertPool()
	if err != nil {
		errMsg := fmt.Sprintf("Error loading system cert pool: %s", err.Error())
		return tls.Certificate{}, nil, fmt.Errorf(errMsg)
	}
	if x.CA == "" {
		if ok := certPool.AppendCertsFromPEM([]byte(x.CertChain)); !ok {
			return tls.Certificate{}, nil, fmt.Errorf("Error while adding CACerts cert pool: \n%s\n", x.CertChain)
		}
	} else {
		if ok := certPool.AppendCertsFromPEM([]byte(x.CA)); !ok {
			return tls.Certificate{}, nil, fmt.Errorf("Error while adding CACerts cert pool: \n%s\n", x.CA)
		}
	}
	return certificate, certPool, nil
}
