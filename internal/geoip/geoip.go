package geoip

import (
  "log"
  "net"

  "github.com/oschwald/geoip2-golang"
)

var db *geoip2.Reader

func Init(dbPath string) error {
  var err error
  db, err = geoip2.Open(dbPath)
  if err != nil {
    return err
  }
  return nil
}

func Close() {
  db.Close()
}

func LookupCountry(ip net.IP) string {
  country, err := db.Country(ip)
  if err != nil {
    log.Printf("Error looking up country for IP %s: %v", ip, err)
    return "Unkown"
  }
  return country.Country.IsoCode
}
