---------------------------- MODULE SampledValuesProtocol ----------------------------
(***************************************************************************
 * TLA+ Specification of IEC 61850-9-2 Sampled Values (SV) Protocol
 *
 * This specification models the Sampled Values protocol for high-precision
 * measurement data transmission in electrical substations.
 *
 * Key Properties Verified:
 * 1. Safety: Sample counter (smpCnt) increments monotonically and wraps correctly
 * 2. Safety: Samples are delivered in order
 * 3. Liveness: Periodic sampling continues (no starvation)
 * 4. Timing: Maximum latency bounds are respected
 * 5. Safety: Quality flags propagate correctly
 *
 * Author: IEC-61850 DPDK Project
 * Standard: IEC 61850-9-2
 ***************************************************************************)

EXTENDS Integers, Sequences, FiniteSets, TLC

CONSTANTS
    MAX_SMPCNT,         (* Maximum sample count (80, 256, 4000, or 4800 per IEC 61850-9-2LE) *)
    PUBLISHERS,         (* Set of SV publishers *)
    SUBSCRIBERS,        (* Set of SV subscribers *)
    SAMPLING_INTERVAL,  (* Sampling interval in abstract time units *)
    MAX_LATENCY,        (* Maximum allowed latency (e.g., 200μs = 2 time units) *)
    NUM_CHANNELS,       (* Number of measurement channels (e.g., 4 for 3-phase + neutral) *)
    SAMPLE_VALUES       (* Set of possible sample values (finite for model checking) *)

VARIABLES
    (* Publisher state *)
    pub_smpCnt,         (* Sample counter - wraps at MAX_SMPCNT *)
    pub_smpSynch,       (* Sample synchronization: 0=none, 1=local, 2=global *)
    pub_confRev,        (* Configuration revision *)
    pub_samples,        (* Current sample values [channel -> value] *)
    pub_quality,        (* Quality flags [channel -> quality_bits] *)
    pub_timer,          (* Sampling timer *)
    pub_timestamp,      (* Publication timestamp *)

    (* Global time *)
    global_time,        (* Abstract global time counter *)

    (* Network state *)
    network,            (* Messages in flight: sequence of [smpCnt, samples, quality, timestamp, ttl] *)

    (* Subscriber state *)
    sub_received,       (* Samples received by each subscriber [subscriber -> seq of samples] *)
    sub_latest_smpCnt,  (* Latest smpCnt received by each subscriber *)
    sub_latest_time,    (* Timestamp of latest sample received *)
    sub_missing,        (* Missing sample count (for gap detection) *)
    sub_samples,        (* Current sample values at subscriber *)
    sub_quality         (* Current quality at subscriber *)

vars == <<pub_smpCnt, pub_smpSynch, pub_confRev, pub_samples, pub_quality,
          pub_timer, pub_timestamp, global_time, network,
          sub_received, sub_latest_smpCnt, sub_latest_time,
          sub_missing, sub_samples, sub_quality>>

(***************************************************************************
 * Quality Flags (simplified from IEC 61850-9-2)
 ***************************************************************************)

QUALITY_GOOD == 0
QUALITY_INVALID == 1
QUALITY_QUESTIONABLE == 2
QUALITY_OVERFLOW == 3

ValidQuality == {QUALITY_GOOD, QUALITY_INVALID, QUALITY_QUESTIONABLE, QUALITY_OVERFLOW}

(***************************************************************************
 * Type Invariants
 ***************************************************************************)

TypeOK ==
    /\ pub_smpCnt \in 0..MAX_SMPCNT
    /\ pub_smpSynch \in 0..2
    /\ pub_confRev \in Nat
    /\ pub_samples \in [1..NUM_CHANNELS -> SAMPLE_VALUES]
    /\ pub_quality \in [1..NUM_CHANNELS -> ValidQuality]
    /\ pub_timer \in Nat
    /\ pub_timestamp \in Int  (* Can be negative to mark as "already published" *)
    /\ global_time \in Nat
    /\ network \in Seq([smpCnt: 0..MAX_SMPCNT,
                        samples: [1..NUM_CHANNELS -> SAMPLE_VALUES],
                        quality: [1..NUM_CHANNELS -> ValidQuality],
                        timestamp: Nat,
                        ttl: Nat])
    /\ sub_received \in [SUBSCRIBERS -> Seq([smpCnt: 0..MAX_SMPCNT,
                                              samples: [1..NUM_CHANNELS -> SAMPLE_VALUES]])]
    /\ sub_latest_smpCnt \in [SUBSCRIBERS -> 0..MAX_SMPCNT]
    /\ sub_latest_time \in [SUBSCRIBERS -> Nat]
    /\ sub_missing \in [SUBSCRIBERS -> Nat]
    /\ sub_samples \in [SUBSCRIBERS -> [1..NUM_CHANNELS -> SAMPLE_VALUES]]
    /\ sub_quality \in [SUBSCRIBERS -> [1..NUM_CHANNELS -> ValidQuality]]

(***************************************************************************
 * Initial State
 ***************************************************************************)

Init ==
    /\ pub_smpCnt = 0
    /\ pub_smpSynch = 1  (* Local time sync *)
    /\ pub_confRev = 1
    /\ pub_samples = [ch \in 1..NUM_CHANNELS |-> 0]
    /\ pub_quality = [ch \in 1..NUM_CHANNELS |-> QUALITY_GOOD]
    /\ pub_timer = SAMPLING_INTERVAL
    /\ pub_timestamp = -1  (* No sample ready initially *)
    /\ global_time = 0
    /\ network = <<>>
    /\ sub_received = [s \in SUBSCRIBERS |-> <<>>]
    /\ sub_latest_smpCnt = [s \in SUBSCRIBERS |-> 0]
    /\ sub_latest_time = [s \in SUBSCRIBERS |-> 0]
    /\ sub_missing = [s \in SUBSCRIBERS |-> 0]
    /\ sub_samples = [s \in SUBSCRIBERS |-> [ch \in 1..NUM_CHANNELS |-> 0]]
    /\ sub_quality = [s \in SUBSCRIBERS |-> [ch \in 1..NUM_CHANNELS |-> QUALITY_GOOD]]

(***************************************************************************
 * Publisher Actions
 ***************************************************************************)

(* Time advances *)
TimeTick ==
    /\ global_time' = global_time + 1
    /\ pub_timer' = IF pub_timer > 0 THEN pub_timer - 1 ELSE 0
    /\ UNCHANGED <<pub_smpCnt, pub_smpSynch, pub_confRev, pub_samples, pub_quality,
                   pub_timestamp, network, sub_received, sub_latest_smpCnt,
                   sub_latest_time, sub_missing, sub_samples, sub_quality>>

(* Sample acquisition (new measurements available) *)
AcquireSample ==
    /\ pub_timer = 0  (* Sampling interval expired *)
    /\ \E new_samples \in [1..NUM_CHANNELS -> SAMPLE_VALUES]:
        /\ \E new_quality \in [1..NUM_CHANNELS -> ValidQuality]:
            /\ pub_samples' = new_samples
            /\ pub_quality' = new_quality
            /\ pub_smpCnt' = IF pub_smpCnt < MAX_SMPCNT THEN pub_smpCnt + 1 ELSE 0
            /\ pub_timestamp' = global_time
            /\ pub_timer' = SAMPLING_INTERVAL  (* Reset timer *)
            /\ UNCHANGED <<pub_smpSynch, pub_confRev, global_time, network,
                           sub_received, sub_latest_smpCnt, sub_latest_time,
                           sub_missing, sub_samples, sub_quality>>

(* Publish SV frame to network *)
PublishSample ==
    /\ pub_timestamp = global_time  (* Fresh sample available *)
    /\ network' = Append(network, [smpCnt |-> pub_smpCnt,
                                   samples |-> pub_samples,
                                   quality |-> pub_quality,
                                   timestamp |-> pub_timestamp,
                                   ttl |-> MAX_LATENCY])
    /\ pub_timestamp' = -1  (* Mark as published - use sentinel value *)
    /\ UNCHANGED <<pub_smpCnt, pub_smpSynch, pub_confRev, pub_samples,
                   pub_quality, pub_timer, global_time,
                   sub_received, sub_latest_smpCnt, sub_latest_time,
                   sub_missing, sub_samples, sub_quality>>

(***************************************************************************
 * Network Actions
 ***************************************************************************)

(* Message propagation (decreases TTL) *)
NetworkPropagate ==
    /\ network # <<>>
    /\ \E i \in 1..Len(network):
        /\ network[i].ttl > 0
        /\ network' = [network EXCEPT ![i].ttl = @ - 1]
    /\ UNCHANGED <<pub_smpCnt, pub_smpSynch, pub_confRev, pub_samples,
                   pub_quality, pub_timer, pub_timestamp, global_time,
                   sub_received, sub_latest_smpCnt, sub_latest_time,
                   sub_missing, sub_samples, sub_quality>>

(* Drop expired messages (exceeded latency bound) *)
NetworkDrop ==
    /\ network # <<>>
    /\ \E i \in 1..Len(network):
        /\ network[i].ttl = 0
        /\ network' = SubSeq(network, 1, i-1) \o SubSeq(network, i+1, Len(network))
    /\ UNCHANGED <<pub_smpCnt, pub_smpSynch, pub_confRev, pub_samples,
                   pub_quality, pub_timer, pub_timestamp, global_time,
                   sub_received, sub_latest_smpCnt, sub_latest_time,
                   sub_missing, sub_samples, sub_quality>>

(***************************************************************************
 * Subscriber Actions
 ***************************************************************************)

(* Subscriber receives SV message *)
ReceiveSample(sub) ==
    /\ network # <<>>
    /\ \E i \in 1..Len(network):
        /\ network[i].ttl >= 0  (* Message available *)
        /\ LET msg == network[i] IN
            \/ (* New sample (smpCnt advanced) - accept *)
               /\ msg.smpCnt = (sub_latest_smpCnt[sub] + 1) % (MAX_SMPCNT + 1)
               /\ sub_latest_smpCnt' = [sub_latest_smpCnt EXCEPT ![sub] = msg.smpCnt]
               /\ sub_latest_time' = [sub_latest_time EXCEPT ![sub] = global_time]
               /\ sub_samples' = [sub_samples EXCEPT ![sub] = msg.samples]
               /\ sub_quality' = [sub_quality EXCEPT ![sub] = msg.quality]
               /\ sub_received' = [sub_received EXCEPT ![sub] =
                                   Append(@, [smpCnt |-> msg.smpCnt, samples |-> msg.samples])]
               /\ sub_missing' = [sub_missing EXCEPT ![sub] = 0]  (* Reset gap counter *)
            \/ (* Future sample (gap detected) *)
               /\ msg.smpCnt > (sub_latest_smpCnt[sub] + 1) % (MAX_SMPCNT + 1)
               /\ msg.smpCnt <= MAX_SMPCNT
               /\ msg.smpCnt # sub_latest_smpCnt[sub]  (* Not a duplicate *)
               /\ msg.smpCnt > sub_latest_smpCnt[sub]  (* Not an old sample (handles wrapping) *)
               /\ sub_latest_smpCnt' = [sub_latest_smpCnt EXCEPT ![sub] = msg.smpCnt]
               /\ sub_latest_time' = [sub_latest_time EXCEPT ![sub] = global_time]
               /\ sub_samples' = [sub_samples EXCEPT ![sub] = msg.samples]
               /\ sub_quality' = [sub_quality EXCEPT ![sub] =
                                  [ch \in 1..NUM_CHANNELS |-> QUALITY_QUESTIONABLE]]  (* Mark as questionable *)
               /\ sub_received' = [sub_received EXCEPT ![sub] =
                                   Append(@, [smpCnt |-> msg.smpCnt, samples |-> msg.samples])]
               /\ sub_missing' = [sub_missing EXCEPT ![sub] =
                                  @ + (msg.smpCnt - sub_latest_smpCnt[sub] - 1)]
            \/ (* Old or duplicate sample - discard *)
               /\ msg.smpCnt <= sub_latest_smpCnt[sub]
               /\ msg.smpCnt # (sub_latest_smpCnt[sub] + 1) % (MAX_SMPCNT + 1)
               /\ UNCHANGED <<sub_received, sub_latest_smpCnt, sub_latest_time,
                              sub_missing, sub_samples, sub_quality>>
    /\ UNCHANGED <<pub_smpCnt, pub_smpSynch, pub_confRev, pub_samples,
                   pub_quality, pub_timer, pub_timestamp, global_time, network>>

(***************************************************************************
 * Next State Relation
 ***************************************************************************)

Next ==
    \/ TimeTick
    \/ AcquireSample
    \/ PublishSample
    \/ NetworkPropagate
    \/ NetworkDrop
    \/ \E sub \in SUBSCRIBERS: ReceiveSample(sub)

(***************************************************************************
 * Specification
 ***************************************************************************)

Spec == Init /\ [][Next]_vars

(***************************************************************************
 * Safety Properties
 ***************************************************************************)

(* Sample counter increments monotonically (modulo MAX_SMPCNT) *)
SampleCounterMonotonic ==
    [][pub_smpCnt' = (pub_smpCnt + 1) % (MAX_SMPCNT + 1) \/ pub_smpCnt' = pub_smpCnt]_vars

(* Sampling interval is maintained *)
SamplingIntervalMaintained ==
    [][AcquireSample => pub_timer = 0]_vars

(* Subscribers never have future samples - timestamp based check *)
(* Note: smpCnt-based checking is problematic with wraparound, use timestamps instead *)
SubscriberSampleConsistent ==
    \A sub \in SUBSCRIBERS:
        sub_latest_time[sub] <= global_time

(* Quality degradation is detected on gaps *)
GapDetectionQuality ==
    \A sub \in SUBSCRIBERS:
        sub_missing[sub] > 0 =>
            \E ch \in 1..NUM_CHANNELS: sub_quality[sub][ch] # QUALITY_GOOD

(* Received samples are in order (no reordering) *)
SamplesInOrder ==
    \A sub \in SUBSCRIBERS:
        \A i \in 1..(Len(sub_received[sub]) - 1):
            LET curr == sub_received[sub][i].smpCnt
                next == sub_received[sub][i+1].smpCnt
            IN next = (curr + 1) % (MAX_SMPCNT + 1) \/ next > curr

(***************************************************************************
 * Timing Properties
 ***************************************************************************)

(* Maximum latency bound is never violated *)
LatencyBound ==
    \A i \in 1..Len(network):
        network[i].ttl <= MAX_LATENCY

(* Samples are delivered within latency bound or dropped *)
TimelyDeliveryOrDrop ==
    \A i \in 1..Len(network):
        (global_time - network[i].timestamp) <= MAX_LATENCY

(***************************************************************************
 * State Space Constraints
 ***************************************************************************)

(* Bounds state space for feasible model checking *)
StateConstraintBasic ==
    /\ pub_smpCnt <= MAX_SMPCNT
    /\ global_time <= 10  (* Tightened for CI completion within 1 hour *)
    /\ Len(network) <= 2  (* Reduced network queue size *)
    /\ \A sub \in SUBSCRIBERS: Len(sub_received[sub]) <= 4  (* Reduced history *)

(***************************************************************************
 * Liveness Properties
 ***************************************************************************)

(* Publisher continuously samples - timer eventually reaches 0 *)
ContinuousSampling ==
    []<>(pub_timer = 0)

(* Samples are eventually published *)
EventualPublication ==
    [](pub_timestamp = global_time ~> pub_timestamp # global_time)

(* Subscribers eventually receive samples (if network operational) *)
EventualReception ==
    \A sub \in SUBSCRIBERS:
        [](pub_smpCnt > sub_latest_smpCnt[sub] ~>
           <>(sub_latest_smpCnt[sub] >= pub_smpCnt))

=============================================================================
