package geoip

import (
    "log"
    "net"
    "strconv"

    "github.com/oschwald/geoip2-golang"
    "github.com/oschwald/maxminddb-golang"
)

var db *geoip2.Reader
var asnDB *maxminddb.Reader

func Init(dbPath string, asnPath string) error {
    var err error
    db, err = geoip2.Open(dbPath)
    if err != nil {
        return err
    }
    asnDB, err = maxminddb.Open(asnPath)
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
        log.Printf("Error looking up country for IP %s: %v", ip, err)
        return "Unknown"
    }
    return country.Country.IsoCode
}

func LookupASN(ip net.IP) (string, string) {
    var record struct {
        ASN       int    `maxminddb:"autonomous_system_number"`
        Org       string `maxminddb:"autonomous_system_organization"`
    }

    err := asnDB.Lookup(ip, &record)
    if err != nil {
        log.Printf("Error looking up ASN for IP %s: %v", ip, err)
        return "N/A", "N/A"
    }

    return strconv.Itoa(record.ASN), record.Org
}

func LookupDomain(ip net.IP) string {
    names, err := net.LookupAddr(ip.String())
    if err != nil || len(names) == 0 {
        log.Printf("Error looking up domain for IP %s: %v", ip, err)
        return ""
    }
    return names[0]
}

