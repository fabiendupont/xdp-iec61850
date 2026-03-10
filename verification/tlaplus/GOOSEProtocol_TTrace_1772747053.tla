---- MODULE GOOSEProtocol_TTrace_1772747053 ----
EXTENDS Sequences, TLCExt, GOOSEProtocol, GOOSEProtocol_TEConstants, Toolbox, Naturals, TLC

_expression ==
    LET GOOSEProtocol_TEExpression == INSTANCE GOOSEProtocol_TEExpression
    IN GOOSEProtocol_TEExpression!expression
----

_trace ==
    LET GOOSEProtocol_TETrace == INSTANCE GOOSEProtocol_TETrace
    IN GOOSEProtocol_TETrace!trace
----

_prop ==
    ~<>[](
        pub_stNum = (1)
        /\
        sub_received = ((sub1 :> FALSE @@ sub2 :> FALSE @@ sub3 :> FALSE @@ sub4 :> FALSE))
        /\
        pub_sqNum = (0)
        /\
        sub_latest_stNum = ((sub1 :> 0 @@ sub2 :> 0 @@ sub3 :> 0 @@ sub4 :> 0))
        /\
        sub_latest_sqNum = ((sub1 :> 0 @@ sub2 :> 0 @@ sub3 :> 0 @@ sub4 :> 0))
        /\
        pub_state = ("PUBLISHING")
        /\
        pub_data = (2)
        /\
        sub_data = ((sub1 :> 0 @@ sub2 :> 0 @@ sub3 :> 0 @@ sub4 :> 0))
        /\
        pub_timer = (0)
        /\
        network = (<<>>)
    )
----

_init ==
    /\ sub_received = _TETrace[1].sub_received
    /\ network = _TETrace[1].network
    /\ pub_state = _TETrace[1].pub_state
    /\ pub_sqNum = _TETrace[1].pub_sqNum
    /\ sub_latest_sqNum = _TETrace[1].sub_latest_sqNum
    /\ pub_stNum = _TETrace[1].pub_stNum
    /\ pub_data = _TETrace[1].pub_data
    /\ sub_latest_stNum = _TETrace[1].sub_latest_stNum
    /\ pub_timer = _TETrace[1].pub_timer
    /\ sub_data = _TETrace[1].sub_data
----

_next ==
    /\ \E i,j \in DOMAIN _TETrace:
        /\ \/ /\ j = i + 1
              /\ i = TLCGet("level")
        /\ sub_received  = _TETrace[i].sub_received
        /\ sub_received' = _TETrace[j].sub_received
        /\ network  = _TETrace[i].network
        /\ network' = _TETrace[j].network
        /\ pub_state  = _TETrace[i].pub_state
        /\ pub_state' = _TETrace[j].pub_state
        /\ pub_sqNum  = _TETrace[i].pub_sqNum
        /\ pub_sqNum' = _TETrace[j].pub_sqNum
        /\ sub_latest_sqNum  = _TETrace[i].sub_latest_sqNum
        /\ sub_latest_sqNum' = _TETrace[j].sub_latest_sqNum
        /\ pub_stNum  = _TETrace[i].pub_stNum
        /\ pub_stNum' = _TETrace[j].pub_stNum
        /\ pub_data  = _TETrace[i].pub_data
        /\ pub_data' = _TETrace[j].pub_data
        /\ sub_latest_stNum  = _TETrace[i].sub_latest_stNum
        /\ sub_latest_stNum' = _TETrace[j].sub_latest_stNum
        /\ pub_timer  = _TETrace[i].pub_timer
        /\ pub_timer' = _TETrace[j].pub_timer
        /\ sub_data  = _TETrace[i].sub_data
        /\ sub_data' = _TETrace[j].sub_data

\* Uncomment the ASSUME below to write the states of the error trace
\* to the given file in Json format. Note that you can pass any tuple
\* to `JsonSerialize`. For example, a sub-sequence of _TETrace.
    \* ASSUME
    \*     LET J == INSTANCE Json
    \*         IN J!JsonSerialize("GOOSEProtocol_TTrace_1772747053.json", _TETrace)

=============================================================================

 Note that you can extract this module `GOOSEProtocol_TEExpression`
  to a dedicated file to reuse `expression` (the module in the 
  dedicated `GOOSEProtocol_TEExpression.tla` file takes precedence 
  over the module `GOOSEProtocol_TEExpression` below).

---- MODULE GOOSEProtocol_TEExpression ----
EXTENDS Sequences, TLCExt, GOOSEProtocol, GOOSEProtocol_TEConstants, Toolbox, Naturals, TLC

expression == 
    [
        \* To hide variables of the `GOOSEProtocol` spec from the error trace,
        \* remove the variables below.  The trace will be written in the order
        \* of the fields of this record.
        sub_received |-> sub_received
        ,network |-> network
        ,pub_state |-> pub_state
        ,pub_sqNum |-> pub_sqNum
        ,sub_latest_sqNum |-> sub_latest_sqNum
        ,pub_stNum |-> pub_stNum
        ,pub_data |-> pub_data
        ,sub_latest_stNum |-> sub_latest_stNum
        ,pub_timer |-> pub_timer
        ,sub_data |-> sub_data
        
        \* Put additional constant-, state-, and action-level expressions here:
        \* ,_stateNumber |-> _TEPosition
        \* ,_sub_receivedUnchanged |-> sub_received = sub_received'
        
        \* Format the `sub_received` variable as Json value.
        \* ,_sub_receivedJson |->
        \*     LET J == INSTANCE Json
        \*     IN J!ToJson(sub_received)
        
        \* Lastly, you may build expressions over arbitrary sets of states by
        \* leveraging the _TETrace operator.  For example, this is how to
        \* count the number of times a spec variable changed up to the current
        \* state in the trace.
        \* ,_sub_receivedModCount |->
        \*     LET F[s \in DOMAIN _TETrace] ==
        \*         IF s = 1 THEN 0
        \*         ELSE IF _TETrace[s].sub_received # _TETrace[s-1].sub_received
        \*             THEN 1 + F[s-1] ELSE F[s-1]
        \*     IN F[_TEPosition - 1]
    ]

=============================================================================



Parsing and semantic processing can take forever if the trace below is long.
 In this case, it is advised to uncomment the module below to deserialize the
 trace from a generated binary file.

\*
\*---- MODULE GOOSEProtocol_TETrace ----
\*EXTENDS IOUtils, GOOSEProtocol, GOOSEProtocol_TEConstants, TLC
\*
\*trace == IODeserialize("GOOSEProtocol_TTrace_1772747053.bin", TRUE)
\*
\*=============================================================================
\*

---- MODULE GOOSEProtocol_TETrace ----
EXTENDS GOOSEProtocol, GOOSEProtocol_TEConstants, TLC

trace == 
    <<
    ([pub_stNum |-> 0,sub_received |-> (sub1 :> FALSE @@ sub2 :> FALSE @@ sub3 :> FALSE @@ sub4 :> FALSE),pub_sqNum |-> 0,sub_latest_stNum |-> (sub1 :> 0 @@ sub2 :> 0 @@ sub3 :> 0 @@ sub4 :> 0),sub_latest_sqNum |-> (sub1 :> 0 @@ sub2 :> 0 @@ sub3 :> 0 @@ sub4 :> 0),pub_state |-> "IDLE",pub_data |-> 0,sub_data |-> (sub1 :> 0 @@ sub2 :> 0 @@ sub3 :> 0 @@ sub4 :> 0),pub_timer |-> 0,network |-> <<>>]),
    ([pub_stNum |-> 1,sub_received |-> (sub1 :> FALSE @@ sub2 :> FALSE @@ sub3 :> FALSE @@ sub4 :> FALSE),pub_sqNum |-> 0,sub_latest_stNum |-> (sub1 :> 0 @@ sub2 :> 0 @@ sub3 :> 0 @@ sub4 :> 0),sub_latest_sqNum |-> (sub1 :> 0 @@ sub2 :> 0 @@ sub3 :> 0 @@ sub4 :> 0),pub_state |-> "PUBLISHING",pub_data |-> 2,sub_data |-> (sub1 :> 0 @@ sub2 :> 0 @@ sub3 :> 0 @@ sub4 :> 0),pub_timer |-> 0,network |-> <<>>])
    >>
----


=============================================================================

---- MODULE GOOSEProtocol_TEConstants ----
EXTENDS GOOSEProtocol

CONSTANTS pub1, sub1, sub2, sub3, sub4

=============================================================================

---- CONFIG GOOSEProtocol_TTrace_1772747053 ----
CONSTANTS
    MAX_STNUM = 8
    MAX_SQNUM = 16
    PUBLISHERS = { pub1 }
    SUBSCRIBERS = { sub1 , sub2 , sub3 , sub4 }
    NETWORK_DELAY = 4
    MAX_RETRANSMITS = 6
    DATA_VALUES = { 0 , 1 , 2 , 3 }
    sub2 = sub2
    sub4 = sub4
    pub1 = pub1
    sub1 = sub1
    sub3 = sub3

PROPERTY
    _prop

CHECK_DEADLOCK
    \* CHECK_DEADLOCK off because of PROPERTY or INVARIANT above.
    FALSE

INIT
    _init

NEXT
    _next

CONSTANT
    _TETrace <- _trace

ALIAS
    _expression
=============================================================================
\* Generated on Thu Mar 05 22:44:16 CET 2026