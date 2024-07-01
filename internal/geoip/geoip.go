package geoip

import (
    "net"

    "github.com/oschwald/geoip2-golang"
    "github.com/lonelysadness/netmonitor/internal/logger"
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
    if db != nil {
        db.Close()
    }
}

func LookupCountry(ip net.IP) string {
    country, err := db.Country(ip)
    if err != nil {
        logger.Log.Printf("Error looking up country for IP %s: %v", ip, err)
        return "Unknown"
    }
    return country.Country.IsoCode
}

