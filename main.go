package main

import (
	"errors"
	"fmt"
	"github.com/PuerkitoBio/goquery"
	influxdb2 "github.com/influxdata/influxdb-client-go/v2"
	"github.com/influxdata/influxdb-client-go/v2/api"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var WhitespaceSplitRe = regexp.MustCompile(`\s+`)

func main() {
	influxAddr, ok := os.LookupEnv("INFLUX_ADDR")
	if !ok {
		log.Fatalln("INFLUX_ADDR not set")
	}
	influxToken, ok := os.LookupEnv("INFLUX_TOKEN")
	if !ok {
		log.Fatalln("INFLUX_TOKEN not set")
	}
	influxOrg, ok := os.LookupEnv("INFLUX_ORG")
	if !ok {
		log.Fatalln("INFLUX_ORG not set")
	}
	influxBucket, ok := os.LookupEnv("INFLUX_BUCKET")
	if !ok {
		log.Fatalln("INFLUX_BUCKET not set")
	}
	routerAddr, ok := os.LookupEnv("ROUTER_ADDR")
	if !ok {
		log.Fatalln("ROUTER_ADDR not set")
	}
	routerUsername, ok := os.LookupEnv("ROUTER_USERNAME")
	if !ok {
		routerUsername = "admin"
	}
	routerPassword, ok := os.LookupEnv("ROUTER_PASSWORD")
	if !ok {
		log.Fatalln("ROUTER_PASSWORD not set")
	}
	rateRaw, ok := os.LookupEnv("SCRAPE_RATE_SECS")
	if !ok {
		rateRaw = "10"
	}
	rate, err := strconv.ParseInt(rateRaw, 10, 64)
	if err != nil {
		log.Panicln(err)
	}

	influxClient := influxdb2.NewClient(influxAddr, influxToken)
	writeAPI := influxClient.WriteAPI(influxOrg, influxBucket)
	errs := writeAPI.Errors()

	go func() {
		for err := range errs {
			log.Println(err)
		}
	}()

	jar, err := cookiejar.New(&cookiejar.Options{})
	if err != nil {
		log.Panicln(err)
	}

	client := http.Client{Jar: jar}
	login(client, routerAddr, routerUsername, routerPassword)

	for {
		extractModemData(client, writeAPI, routerAddr, routerUsername, routerPassword)
		time.Sleep(time.Duration(rate) * time.Second)
	}
}

func login(client http.Client, routerAddr string, routerUsername string, routerPassword string) {
	res, err := client.PostForm(fmt.Sprintf("%s/check.php", routerAddr), url.Values{
		"username": {routerUsername},
		"password": {routerPassword},
	})
	if err != nil {
		log.Panicln(err)
	}

	bodyRaw, err := io.ReadAll(res.Body)
	if strings.Contains(string(bodyRaw), "alert(\"Incorrect ") {
		log.Panicln("Incorrect user name or password")
	}
	return
}

func extractModemData(client http.Client, writeAPI api.WriteAPI, routerAddr string, routerUsername string, routerPassword string) {
	var res, err = client.Get(fmt.Sprintf("%s/network_setup.php", routerAddr))
	if err != nil {
		log.Panicln(err)
	}
	bodyRaw, err := io.ReadAll(res.Body)
	body := string(bodyRaw)

	if strings.Contains(body, "alert(\"Please Login First!\");") {
		login(client, routerAddr, routerUsername, routerPassword)
		return
	}

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(body))
	if err != nil {
		log.Panicln(err)
	}

	downstreamColumns := extractIndexedTable(doc, 13)
	downstreamEntries := columnsToMaps(downstreamColumns)
	reportDownstreamEntries(downstreamEntries, writeAPI)

	upstreamColumns := extractIndexedTable(doc, 14)
	upstreamEntries := columnsToMaps(upstreamColumns)
	reportUpstreamEntries(upstreamEntries, writeAPI)

	codewordsColumns := extractIndexedTable(doc, 15)
	codewordsEntries := columnsToMaps(codewordsColumns)
	reportCodewordEntries(codewordsEntries, writeAPI)

	writeAPI.Flush()
}

func reportDownstreamEntries(entries []map[string]string, writeAPI api.WriteAPI) {
	for _, entry := range entries {
		//log.Printf("%d %#v\n", i, entry)
		tags := make(map[string]string)
		fields := make(map[string]interface{})

		if index, ok := entry["Index"]; ok {
			tags["index"] = index
		} else {
			log.Panicln("No index", entry)
		}

		if modulation, ok := entry["Modulation"]; ok {
			fields["modulation"] = modulation
		}

		if lockStatus, ok := entry["Lock Status"]; ok {
			fields["lock_status"] = lockStatus
		}

		if rawFreq, ok := entry["Frequency"]; ok {
			if freq, err := parseFreq(rawFreq); err == nil {
				fields["frequency"] = freq
			} else {
				log.Panicln(err)
			}
		}

		if rawSNR, ok := entry["SNR"]; ok {
			if snr, err := parseSNR(rawSNR); err == nil {
				fields["snr"] = snr
			} else {
				if _, ok := err.(noneError); !ok {
					log.Panicln(err)
				}
			}
		}

		if rawPowerLevel, ok := entry["Power Level"]; ok {
			if powerLevel, err := parsePowerLevel(rawPowerLevel); err == nil {
				fields["power_level"] = powerLevel
			} else {
				if _, ok := err.(noneError); !ok {
					log.Panicln(err)
				}
			}
		}

		p := influxdb2.NewPoint("downstream_channels",
			tags,
			fields,
			time.Now())
		writeAPI.WritePoint(p)
	}
}

func reportUpstreamEntries(entries []map[string]string, writeAPI api.WriteAPI) {
	for _, entry := range entries {
		tags := make(map[string]string)
		fields := make(map[string]interface{})

		if index, ok := entry["Index"]; ok {
			tags["index"] = index
		} else {
			log.Panicln("No index", entry)
		}

		if modulation, ok := entry["Modulation"]; ok {
			fields["modulation"] = modulation
		}

		if lockStatus, ok := entry["Lock Status"]; ok {
			fields["lock_status"] = lockStatus
		}

		if channelType, ok := entry["Channel Type"]; ok {
			fields["channel_type"] = channelType
		}

		if rawFreq, ok := entry["Frequency"]; ok {
			if freq, err := parseFreq(rawFreq); err == nil {
				fields["frequency"] = freq
			} else {
				log.Panicln(err)
			}
		}

		if rawSymbolRate, ok := entry["Symbol Rate"]; ok {
			if symbolRate, err := strconv.Atoi(rawSymbolRate); err == nil {
				fields["symbol_rate"] = symbolRate
			} else {
				log.Panicln(err)
			}
		}

		if rawPowerLevel, ok := entry["Power Level"]; ok {
			if powerLevel, err := parsePowerLevel(rawPowerLevel); err == nil {
				fields["power_level"] = powerLevel
			} else {
				if _, ok := err.(noneError); !ok {
					log.Panicln(err)
				}
			}
		}

		p := influxdb2.NewPoint("upstream_channels",
			tags,
			fields,
			time.Now())
		writeAPI.WritePoint(p)
	}
}

func reportCodewordEntries(entries []map[string]string, writeAPI api.WriteAPI) {
	for _, entry := range entries {
		//log.Printf("%d %#v\n", i, entry)
		tags := make(map[string]string)
		fields := make(map[string]interface{})

		if index, ok := entry["Index"]; ok {
			tags["index"] = index
		} else {
			log.Panicln("No index", entry)
		}

		if rawUnerrored, ok := entry["Unerrored Codewords"]; ok {
			if unerrored, err := strconv.ParseInt(rawUnerrored, 10, 64); err == nil {
				fields["unerrored_codewords"] = unerrored
			} else {
				log.Panicln(err)
			}
		}

		if rawCorrectable, ok := entry["Correctable Codewords"]; ok {
			if correctable, err := strconv.ParseInt(rawCorrectable, 10, 64); err == nil {
				fields["correctable_codewords"] = correctable
			} else {
				log.Panicln(err)
			}
		}

		if rawUncorrectable, ok := entry["Uncorrectable Codewords"]; ok {
			if correctable, err := strconv.ParseInt(rawUncorrectable, 10, 64); err == nil {
				fields["uncorrectable_codewords"] = correctable
			} else {
				log.Panicln(err)
			}
		}

		p := influxdb2.NewPoint("cm_codewords",
			tags,
			fields,
			time.Now())
		writeAPI.WritePoint(p)
	}
}

type noneError struct {
}

func (e noneError) Error() string {
	return "NA"
}

func parseSNR(snr string) (float64, error) {
	if snr == "NA" {
		return 0, noneError{}
	}

	parts := strings.Split(snr, " ")
	if len(parts) == 1 {
		return strconv.ParseFloat(parts[0], 64)
	} else if len(parts) == 2 {
		switch parts[1] {
		case "dB":
			snr, err := strconv.ParseFloat(parts[0], 64)
			if err != nil {
				return 0, err
			}
			return snr, nil
		default:
			return 0, errors.New(fmt.Sprintf("Unknown unit: %v", parts[1]))
		}
	} else {
		return 0, errors.New(fmt.Sprintf("Got more than 2 SNR parts: %v", parts))
	}
}

func parsePowerLevel(powerLevel string) (float64, error) {
	if powerLevel == "NA" {
		return 0, noneError{}
	}

	parts := WhitespaceSplitRe.Split(powerLevel, -1)
	if len(parts) == 1 {
		return strconv.ParseFloat(parts[0], 64)
	} else if len(parts) == 2 {
		switch parts[1] {
		case "dBmV":
			powerLevel, err := strconv.ParseFloat(parts[0], 64)
			if err != nil {
				return 0, err
			}
			return powerLevel, nil
		default:
			return 0, errors.New(fmt.Sprintf("Unknown unit: %v", parts[1]))
		}
	} else {
		return 0, errors.New(fmt.Sprintf("Got more than 2 power level parts: %v", parts))
	}
}

func parseFreq(freq string) (int, error) {
	parts := WhitespaceSplitRe.Split(freq, -1)
	if len(parts) == 1 {
		return strconv.Atoi(parts[0])
	} else if len(parts) == 2 {
		switch parts[1] {
		case "MHz":
			freq, err := strconv.Atoi(parts[0])
			if err != nil {
				return 0, err
			}
			return freq * 1000 * 1000, nil
		default:
			return 0, errors.New(fmt.Sprintf("Unknown unit: %v", parts[1]))
		}
	} else {
		return 0, errors.New(fmt.Sprintf("Got more than 2 freq parts: %v", parts))
	}
}

func columnsToMaps(columns [][]string) []map[string]string {
	out := make([]map[string]string, 0)
	for i, column := range columns {
		if i == 0 {
			continue
		}
		attrs := make(map[string]string)
		for i2, attr := range column {
			attrs[columns[0][i2]] = attr
		}
		out = append(out, attrs)
	}

	return out
}

func extractIndexedTable(doc *goquery.Document, index int) [][]string {
	numDownstreamChannels := doc.Find(fmt.Sprintf("#content > div:nth-child(%d) > table > tbody > tr:nth-child(1) > *", index)).Length()
	columns := make([][]string, numDownstreamChannels)

	doc.Find(fmt.Sprintf("#content > div:nth-child(%d) > table > tbody", index)).Children().Each(func(ir int, row *goquery.Selection) {
		row.ChildrenFiltered("*").Each(func(id int, item *goquery.Selection) {
			columns[id] = append(columns[id], strings.TrimSpace(item.Text()))
		})
	})
	return columns
}
