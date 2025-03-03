package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type Subscriber struct {
	Mode         string
	LeaseSeconds string
	Secret       string
}

type Subscribers map[string]Subscriber
type Topics map[string]Subscribers

var (
	modes = map[string]struct{}{"subscribe": {}, "unsubscribe": {}}
	log   = logrus.New()
)

type SubscribeMessage struct {
	Callback     string `json:"hub.callback"`
	Mode         string `json:"hub.mode"`
	Topic        string `json:"hub.topic"`
	LeaseSeconds string `json:"hub.lease_seconds"`
	Secret       string `json:"hub.secret"`
}

type TestData struct {
	Test string `json:"test"`
}

type Hub struct {
	topics Topics
	lock   sync.Mutex
}

func newHub(topics *Topics) *Hub {
	return &Hub{topics: *topics}
}

func (hub *Hub) updateSubscriber(subMsg *SubscribeMessage) error {
	hub.lock.Lock()
	defer hub.lock.Unlock()

	if subscribers, ok := hub.topics[subMsg.Topic]; ok {
		newSub := &Subscriber{Mode: subMsg.Mode, LeaseSeconds: subMsg.LeaseSeconds, Secret: subMsg.Secret}
		subscribers[subMsg.Callback] = *newSub
		return nil
	}
	return fmt.Errorf("topic %s does not exist", subMsg.Topic)
}

func (hub *Hub) removeSubscriber(subMsg *SubscribeMessage) error {
	hub.lock.Lock()
	defer hub.lock.Unlock()

	if subscribers, ok := hub.topics[subMsg.Topic]; ok {
		if _, ok := subscribers[subMsg.Callback]; !ok {
			return fmt.Errorf("tried to remove subscription for a callback url %s that does not exist", subMsg.Callback)
		}
		delete(subscribers, subMsg.Callback)
		return nil
	}
	return fmt.Errorf("topic %s does not exist", subMsg.Topic)
}

func (hub *Hub) verifyIntent(subMsg *SubscribeMessage) {
	log.Infof("Verifying intent of %s", subMsg.Callback)
	client := &http.Client{}

	req, err := http.NewRequest("GET", subMsg.Callback, nil)
	if err != nil {
		log.Errorf("failed to create verification message: %s", err)
		return
	}

	q := req.URL.Query()
	q.Add("hub.mode", subMsg.Mode)
	q.Add("hub.topic", subMsg.Topic)

	challenge := uuid.New().String()
	q.Add("hub.challenge", challenge)
	req.URL.RawQuery = q.Encode()

	resp, err := client.Do(req)
	if err != nil {
		log.Errorf("failed to send verification request to subscriber with callback url %s", subMsg.Callback)
		return
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Errorf("error when reading the body of the request: %s", err)
		return
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Errorf("invalid reponse code from subscriber with callback url %s", subMsg.Callback)
		return
	}

	if challenge != string(b) {
		log.Errorf("incorrect challenge returned by subscriber with callback url %s", subMsg.Callback)
		return
	}

	// Mode has been verified to be either subscribe or unsubscribed in an earlier step, hence why I can use else here
	if subMsg.Mode == "subscribe" {
		if err := hub.updateSubscriber(subMsg); err != nil {
			log.Errorf("failed to add subscriber: %s", err)
			return
		}
	} else {
		if err := hub.removeSubscriber(subMsg); err != nil {
			log.Errorf("failed to remove subscriber: %s", err)
			return
		}
	}
}

func (hub *Hub) subscribeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		log.Errorf("Method not allowed for subscribe message sent from")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	b, err := io.ReadAll(r.Body)
	if err != nil {
		log.Errorf("Error when reading the body of the request: %s", err)
		http.Error(w, "Could not read the body of the http-request", http.StatusBadRequest)
		return
	}

	m, e := url.ParseQuery(string(b))
	if e != nil {
		log.Errorf("Error when parsing query as url-encoded: %s", e)
		http.Error(w, "Could not parse body as url-encoded", http.StatusBadRequest)
		return
	}

	subMsg := &SubscribeMessage{}

	if val := m.Get("hub.callback"); val == "" {
		log.Errorf("hub.callback not set in subscribe request!")
		http.Error(w, "hub.callback not set in subscribe request!", http.StatusBadRequest)
		return
	} else {
		subMsg.Callback = val
	}

	if val := m.Get("hub.topic"); val == "" {
		log.Errorf("hub.topic not set in subscribe request!")
		http.Error(w, "hub.topic not set in subscribe request!", http.StatusBadRequest)
		return
	} else {
		hub.lock.Lock()
		_, ok := hub.topics[val]
		hub.lock.Unlock()
		if !ok {
			retErr := fmt.Errorf("topic %s does not exist", val)
			log.Error(retErr.Error())
			http.Error(w, retErr.Error(), http.StatusBadRequest)
			return
		}
		subMsg.Topic = val
	}

	if val := m.Get("hub.mode"); val == "" {
		log.Errorf("hub.mode not set in subscribe request!")
		http.Error(w, "hub.mode not set in subscribe request!", http.StatusBadRequest)
		return
	} else if _, ok := modes[val]; !ok {
		retErr := fmt.Errorf("%s not a acceptable mode", val)
		log.Error(retErr)
		http.Error(w, retErr.Error(), http.StatusBadRequest)
		return
	} else {
		subMsg.Mode = val
	}

	if val := m.Get("hub.lease_seconds"); val != "" {
		subMsg.LeaseSeconds = val
	}

	if val := m.Get("hub.secret"); val != "" {
		subMsg.Secret = val
	}

	go hub.verifyIntent(subMsg)

	w.WriteHeader(http.StatusAccepted)
}

func generateSignature(secret string, body *[]byte) string {
	h := hmac.New(sha1.New, []byte(secret))
	h.Write(*body)
	return "sha1=" + hex.EncodeToString(h.Sum(nil))
}

func sendRequest(callbackUrl string, secret string, topic string, jsonData *[]byte) error {
	req, err := http.NewRequest("POST", callbackUrl, bytes.NewBuffer(*jsonData))
	if err != nil {
		return fmt.Errorf("error creating request: %s", err)
	}

	req.Header.Set("Content-Type", "application/json")
	signature := generateSignature(secret, jsonData)
	req.Header.Set("X-Hub-Signature", signature)

	// Subscriber client does not seem to validate that this link headers are included in the request,
	// but added them anyway
	req.Header.Set("Link", `hub:8080; rel="hub"`)
	req.Header.Set("Link", fmt.Sprintf("%s; rel=\"self\"", topic))

	// Send the request using the default HTTP client
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error sending request: %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 && resp.StatusCode > 299 {
		return fmt.Errorf("status code %d returned from client %s when sending data", resp.StatusCode, callbackUrl)
	}

	return nil
}

func (hub *Hub) publishHandler(w http.ResponseWriter, r *http.Request) {
	hub.lock.Lock()
	defer hub.lock.Unlock()

	if r.Method != http.MethodGet {
		log.Errorf("Method not allowed for subscribe message sent from")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	for topic, subscribers := range hub.topics {
		log.Infof("Generating json data for topic %s", topic)
		data := TestData{
			Test: "test",
		}
		jsonData, err := json.Marshal(data)
		if err != nil {
			log.Fatal("Error marshaling data: ", err)
		}
		for callback, subInfo := range subscribers {
			if err := sendRequest(callback, subInfo.Secret, topic, &jsonData); err != nil {
				log.Errorf("Failed to send generated json data to %s: %s", callback, err)
			}
		}
	}
	w.WriteHeader(http.StatusOK)
}

func main() {
	topics := &Topics{"/a/topic": {}}
	hub := newHub(topics)
	http.HandleFunc("/subscribe", hub.subscribeHandler)
	http.HandleFunc("/publish", hub.publishHandler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
