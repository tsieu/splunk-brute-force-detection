# **Brute Force Login Detection (Splunk SPL)**

## **Detection Objective**

Detect potential brute force login attempts by identifying excessive failed authentication attempts within a short time window.

---

## **Data Source**

* Dataset: BOTS v4

* Index: `botsv4`

* Relevant Field: `action=failure`

* Log Type: Authentication events

---

## **Detection Logic**

Brute force attacks typically generate multiple failed login attempts in a short period of time against a single account.

To detect this behavior:

* Filter for failed login events

* Group activity into 5 minute time windows

* Aggregate by user

* Trigger when failure count exceeds threshold

---

## **SPL Query**

index=botsv4 action=failure  
| bucket \_time span=5m  
| stats count by \_time user  
| where count \> 5  
| sort \-count  
---

## **Why This Works**

* `bucket _time span=5m`  
   Creates fixed time windows to measure behavior patterns.

* `stats count by _time user`  
   Aggregates failed attempts per user within each window.

* `where count > 5`  
   Applies threshold tuning to filter suspicious behavior.

* `sort -count`  
   Surfaces the most aggressive activity first.

---

## **Threshold Tuning**

The threshold (\>5) was selected after observing dataset baseline behavior.

In a production environment, this value should be adjusted based on:

* Normal authentication patterns

* Account lockout policies

* Service account behavior

---

## **Potential False Positives**

* User mistyping password repeatedly

* Automated retry from misconfigured application

* Expired password attempts

---

## **Possible Enhancements**

* Add `dc(src)` to detect distributed brute-force attempts

* Correlate failure events followed by `action=success`

* Exclude known service accounts

* Convert into scheduled alert

---

## **Skills Demonstrated**

* SPL aggregation (`stats`)

* Time window analysis (`bucket`)

* Threshold tuning

* Behavioral detection logic

* Security event analysis

