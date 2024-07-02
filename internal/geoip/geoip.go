package geoip

import (
    "net"

    "github.com/oschwald/geoip2-golang"
    "github.com/lonelysadness/netmonitor/internal/logger"
)

var db *geoip2.Reader
var asnDB *geoip2.Reader

func Init(geoipPath string, asnPath string) error {
    var err error
    db, err = geoip2.Open(geoipPath)
    if err != nil {
        return err
    }

    asnDB, err = geoip2.Open(asnPath)
    if err != nil {
        return err
    }
    return nil
}

func Close() {
    if db != nil {
        db.Close()
    }
    if asnDB != nil {
        asnDB.Close()
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

func LookupASN(ip net.IP) (string, uint, string) {
    record, err := asnDB.ASN(ip)
    if err != nil {
        logger.Log.Printf("Error looking up ASN for IP %s: %v", ip, err)
        return "Unknown", 0, "Unknown"
    }
    return record.AutonomousSystemOrganization, record.AutonomousSystemNumber, ""
}

