<?xml version="1.1" encoding="UTF-8" ?>
<Package PackName="ADG_METRIC_TREE_db2oraclemigration" Type="INTERNAL" Version="7.3.4.1" SupportedServer="ALL" Display="ADG Metric Tree for db2oraclemigration" DatabaseKind="KB_CENTRAL" Description="">
	<Include>
	</Include>
	<Exclude>
	</Exclude>
	<Install>
    </Install>
	<Update>
    </Update>
	<Refresh>
		<Step Type="DATA" File="AdgMetrics_db2oraclemigration.xml" Model="..\assessment_model_tables.xml" Scope="db2oraclemigrationScope"></Step>
	</Refresh>
	<Remove>
	</Remove>
</Package>