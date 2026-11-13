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
        <LDevice 