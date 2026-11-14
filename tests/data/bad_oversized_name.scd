<?xml version="1.0" encoding="UTF-8"?>
<!--
  Negative fixture — WP-6e bounds discipline.
  The GSEControl name exceeds IEC61850_SCL_MAX_NAME (64); the parser
  must reject the document with -ENAMETOOLONG instead of truncating.
-->
<SCL version="2007">
  <IED name="IED1">
    <AccessPoint name="AP1">
      <Server>
        <LDevice inst="LD0">
          <LN0 lnClass="LLN0" inst="" lnType="LLN0">
            <GSEControl name="gcb01_with_an_intentionally_oversized_name_that_exceeds_the_64_character_buffer_limit"
                        datSet="DS1" confRev="1" appID="GOOSE1"/>
          </LN0>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
</SCL>
