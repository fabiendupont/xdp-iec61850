<?xml version="1.0" encoding="UTF-8"?>
<SCL xmlns="http://www.iec.ch/61850/2003/SCL" version="2007">
  <Communication>
    <SubNetwork name="SN1" type="8-MMS">
      <ConnectedAP iedName="IED1" apName="AP1">
        <GSE ldInst="LD0" cbName="gcb01">
          <Address>
            <P type="APPID">0001</P>
            <P type="MAC-Address">01-0C-CD-01-00-01</P>
            <P type="VLAN-ID">100</P>
            <P type="VLAN-PRIORITY">4</P>
          </Address>
          <MinTime unit="s" multiplier="m">2</MinTime>
          <MaxTime unit="s" multiplier="m">2000</MaxTime>
        </GSE>
        <SMV ldInst="LD0" cbName="MSVCB01">
          <Address>
            <P type="APPID">4000</P>
            <P type="MAC-Address">01-0C-CD-04-00-01</P>
            <P type="VLAN-ID">100</P>
            <P type="VLAN-PRIORITY">4</P>
          </Address>
        </SMV>
      </ConnectedAP>
    </SubNetwork>
  </Communication>
  <IED name="IED1" manufacturer="Test">
    <AccessPoint name="AP1">
      <Server>
        <LDevice inst="LD0">
          <LN0 lnClass="LLN0" inst="" lnType="LLN0Type">
            <DataSet name="DS1">
              <FCDA ldInst="LD0" lnClass="XCBR" lnInst="1" doName="Pos" daName="stVal" fc="ST"/>
              <FCDA ldInst="LD0" lnClass="XCBR" lnInst="1" doName="Pos" daName="q" fc="ST"/>
            </DataSet>
            <DataSet name="DS_SV">
              <FCDA ldInst="LD0" lnClass="MMXU" lnInst="1" doName="PhV" daName="phsA" fc="MX"/>
              <FCDA ldInst="LD0" lnClass="MMXU" lnInst="1" doName="PhV" daName="phsB" fc="MX"/>
              <FCDA ldInst="LD0" lnClass="MMXU" lnInst="1" doName="PhV" daName="phsC" fc="MX"/>
              <FCDA ldInst="LD0" lnClass="MMXU" lnInst="1" doName="A" daName="phsA" fc="MX"/>
            </DataSet>
            <GSEControl name="gcb01" datSet="DS1" confRev="1" appID="GOOSE1" goID="GOOSE_ID_1"/>
            <SampledValueControl name="MSVCB01" datSet="DS_SV" confRev="1" smvID="SV_PUB_1" smpRate="80" nofASDU="1"/>
            <ReportControl name="URCB01" rptID="URCB01" datSet="DS1" confRev="1" buffered="false" rptEnabled="3">
              <TrgOps dchg="true" qchg="true" dupd="false" period="false" gi="true"/>
              <OptFields seqNum="true" timeStamp="true" reasonCode="true" dataRef="false" entryID="false" bufOvfl="false" configRef="false"/>
            </ReportControl>
            <ReportControl name="BRCB01" rptID="BRCB01" datSet="DS1" confRev="1" buffered="true" bufTime="500" intgPd="10000" rptEnabled="1">
              <TrgOps dchg="true" qchg="true" dupd="true" period="true" gi="true"/>
              <OptFields seqNum="true" timeStamp="true" reasonCode="true" dataRef="true" entryID="true" bufOvfl="true" configRef="true"/>
            </ReportControl>
          </LN0>
          <LN lnClass="LPHD" inst="1" lnType="LPHDType"/>
          <LN lnClass="XCBR" inst="1" lnType="XCBRType"/>
          <LN lnClass="MMXU" inst="1" lnType="MMXUType"/>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
  <DataTypeTemplates>
    <LNodeType id="LLN0Type" lnClass="LLN0">
      <DO name="Beh" type="INS_1"/>
      <DO name="Health" type="INS_1"/>
      <DO name="Mod" type="INC_1"/>
    </LNodeType>
    <LNodeType id="LPHDType" lnClass="LPHD">
      <DO name="PhyHealth" type="INS_1"/>
      <DO name="Proxy" type="SPS_1"/>
    </LNodeType>
    <LNodeType id="XCBRType" lnClass="XCBR">
      <DO name="Pos" type="DPC_1"/>
      <DO name="BlkOpn" type="SPS_1"/>
      <DO name="BlkCls" type="SPS_1"/>
      <DO name="Beh" type="INS_1"/>
    </LNodeType>
    <LNodeType id="MMXUType" lnClass="