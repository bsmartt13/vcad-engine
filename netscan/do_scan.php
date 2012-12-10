<?php
/*****************************************************************************
*
*    License:
*
*   Copyright (c) 2003-2006 ossim.net
*   Copyright (c) 2007-2009 AlienVault
*   All rights reserved.
*
*   This package is free software; you can redistribute it and/or modify
*   it under the terms of the GNU General Public License as published by
*   the Free Software Foundation; version 2 dated June, 1991.
*   You may not use, modify or distribute this program under any other version
*   of the GNU General Public License.
*
*   This package is distributed in the hope that it will be useful,
*   but WITHOUT ANY WARRANTY; without even the implied warranty of
*   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*   GNU General Public License for more details.
*
*   You should have received a copy of the GNU General Public License
*   along with this package; if not, write to the Free Software
*   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
*   MA  02110-1301  USA
*
*
* On Debian GNU/Linux systems, the complete text of the GNU General
* Public License can be found in `/usr/share/common-licenses/GPL-2'.
*
* Otherwise you can read it here: http://www.gnu.org/licenses/gpl-2.0.txt
****************************************************************************/
/**
* Class and Function List:
* Function list:
* Classes list:
*/
// menu authentication

ob_implicit_flush();

require_once ('classes/Session.inc');
require_once ('classes/Security.inc');
Session::logcheck("MenuPolicy", "ToolsScan");
ini_set("max_execution_time","1200");

require_once 'classes/Security.inc';

$assets          = array();
$full_scan       = "";
$timing_template = "";
$only_stop       = 0;
$only_status     = 0;
$info_error      = array();
$validate_all    = "";
$custom_ports    = "";
$sensor          = "";

$debug = false;

foreach($_GET as $key => $value) {
    $$key = $value;
}

$autodetect      = (GET('autodetect') == "1") ? 1 : 0;
$rdns            = (GET('rdns') == "1") ? 1 : 0;
$vcad            = (GET('vcad') == "1") ? 1 : 0;
$custom_ports    = str_replace(" ", "", $custom_ports);
        
ossim_valid($full_scan,       OSS_ALPHA, OSS_SCORE, OSS_NULLABLE,                 'illegal:' . _("Full scan"));
ossim_valid($timing_template, OSS_ALPHA, OSS_PUNC, OSS_NULLABLE,                  'illegal:' . _("Timing_template"));
ossim_valid($custom_ports,    OSS_DIGIT, OSS_SPACE, OSS_SCORE, OSS_NULLABLE, ',', 'illegal:' . _("Custom Ports"));
ossim_valid($sensor,          OSS_HEX, OSS_ALPHA, OSS_NULLABLE,                   'illegal:' . _("Sensor"));
ossim_valid($only_stop,       OSS_DIGIT, OSS_NULLABLE,                            'illegal:' . _("Only stop"));
ossim_valid($only_status,     OSS_DIGIT, OSS_NULLABLE,                            'illegal:' . _("Only status"));

if ( ossim_error() ){ 
    $info_error[] = ossim_get_error();
}

ossim_clean_error();

$assets_string = "";

$error         = false;
$aux           = array();

$db   = new ossim_db();
$conn = $db->connect();

if($debug) {
    error_log("assets(1): ".serialize($assets)."\n",3,"/tmp/net_scan.log");
}

foreach ($assets as $asset)
{
    $asset_data = explode("#", $asset);  // for example: 23C9D71454562726D00160BB45A61369#10.200.200.1 or 10.200.200.1
    
    if ( count($asset_data) == 2 ) 
	{
        ossim_valid($asset_data[0], OSS_HEX,         'illegal:' . _("Asset Id")); // host id or net id
        ossim_valid($asset_data[1], OSS_IP_ADDRCIDR, 'illegal:' . _("Assets"));   // IP o CIDR
    }
    else {
        ossim_valid($asset, OSS_IP_ADDRCIDR, 'illegal:' . _("Assets")); // IP o CIDR
    }
        
    if ( ossim_error() )
    {
        $info_error[] = ossim_get_error();
        break;
    }
    else
    {
        if ( !preg_match('/\/\d{1,2}$/', $asset) )
            $aux[] = $asset."/32";
        else {
            $aux[] = $asset;
        }
    }
    ossim_clean_error();
}

if( $debug ) {
    error_log("assets(2): ".serialize($aux)."\n",3,"/tmp/net_scan.log");
}

$assets_string .= implode(" ", $aux);

$db->close($conn);

if ( $validate_all == 'true' )
{
	// only validate parameters via ajax
	if ( empty($info_error) )
		echo "1";
	else
		echo "<div style='text-align: left; padding: 0px 0px 3px 10px;'>"._("We found the following errors").":</div><div class='error_item'>".utf8_encode(implode("</div><div class='error_item'>", $info_error))."</div>";
		
	exit();
}
else
{
	if (!empty($info_error))
	{
		?>
		<script type="text/javascript">
			parent.$('#scan_button').removeAttr('disabled');
			parent.$('#scan_button').removeClass();
			parent.$('#scan_button').addClass('button');
		</script>
		<?php
		exit();
	}
}

$assets        = $assets_string;
$scan_path_log = "/tmp/nmap_scanning_".md5(Session::get_secure_id()).".log";

$warning_msg = "";

require_once ('classes/Scan.inc');

// Only Stop
if ($only_stop) 
{
	$scan = new Scan($assets);
	$scan->stop_nmap(); 
	exit();
}

// Launch scan
if (!$only_status && !$only_stop) 
{
	// This object is only for checking available sensors
    $rscan     = new RemoteScan($assets,($full_scan=="full") ? "root" : "ping");
    $available = $rscan->available_scan(preg_match("/[0-9A-F]{32}/i", $sensor) ? $sensor : "");
    $remote_sensor = "null"; // default runs local scan
    unset($_SESSION['_remote_sensor_scan']);

    if (preg_match("/[0-9A-F]{32}/i", $sensor)) { // selected sensor
        if ($available == "") { // not available remote scans, runs local
            $remote_sensor = "null";
            $warning_msg = _("Warning: The selected sensor is not available for remote scan. Using automatic option...");
         } else { // runs remote
            $remote_sensor = $sensor;
            $_SESSION['_remote_sensor_scan'] = $sensor;
         }
    }

    if ($sensor == "auto" && $available != "") { // runs auto select
        $remote_sensor = $available;
        $_SESSION['_remote_sensor_scan'] = $available;
    }
		
    // Launch scan in background
	$cmd = "/usr/bin/php /usr/share/ossim/scripts/vulnmeter/remote_nmap.php '$assets' '$remote_sensor' '$timing_template' '$full_scan' '".$rscan->nmap_completed_scan."' '$autodetect' '$rdns' '$custom_ports' > $scan_path_log 2>&1 &";
	
    if($debug) {
        error_log("cmd :".$cmd."\n",3,"/tmp/net_scan.log");
    }
	if ( file_exists($rscan->nmap_completed_scan) ) 
		@unlink($rscan->nmap_completed_scan);
	
	system($cmd);
}

session_write_close();

?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html>
<head>
	<title> <?php echo gettext("OSSIM Framework"); ?> </title>
	<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1"/>
	<meta http-equiv="Pragma" content="no-cache"/>
	<link rel="stylesheet" type="text/css" href="../style/style.css"/>
	<script type="text/javascript" src="../js/jquery.min.js"></script>
	<script type="text/javascript">
		
		function setIframeHeight(id)
		{
			var elem = parent.document.getElementById(id);
					
			if(elem.contentDocument){
				var height = elem.contentDocument.body.offsetHeight + 35;
			}
			else{ 
				var height = elem.contentWindow.document.body.scrollHeight + 35;
			}
				
			if ( height > 200 ){
				parent.$('#'+id).css('height', height+'px');
			}
		}
						
	</script>
	
	<style type='text/css'>
		body { background: transparent; }
		a {cursor: pointer;}
		
		.loading_nmap {
			width: 99%; 
			height: 99%; 
			background: transparent;
			padding-bottom: 10px;
			text-align: left;
			
		}
		
		.loading_nmap span{
			margin-right: 5px;
		}
		
		.loading_nmap img { margin-right: 5px;}
		
		.ossim_error { width: auto;}
		
		.error_item { padding-left: 30px}
				
	</style>
	
</head>

<body>

<div id='res_container'>

<?php

while( Scan::scanning_now() ) 
{
    if($debug) {
        error_log("Waiting scan...\n",3,"/tmp/net_scan.log");
    }
	
    sleep(3);
}

$has_results = false;

if($vcad)
{
  $output = shell_exec('python /usr/share/ossim-framework/ossimframework/testClass.py');
  //$handle = fopen("/usr/share/ossim/www/vulnmeter/log.txt", "w+");
  //fwrite($handle, $output);
  //fclose($handle);
}

if ( file_exists($scan_path_log) ) 
{
	$has_results = true;
	$output      = file($scan_path_log);
	
	echo "<div style='margin:auto; text-align: center; padding: 5px 0px'>
			<span style='font-weight: bold;'>"._("Scan completed")."</span><a onclick=\"parent.document.location.href='index.php'\"> [ "._("Click here to view the results")."]</a>
		  </div>\n";

	echo "<br/><br/>";

	foreach ($output as $line) 
	{
		if (!preg_match("/appears to be up/",$line)) {
			echo $line."\n";
		}
	}
	
	@unlink($scan_path_log);
}

echo "<br/>";

if($debug) {
    error_log("has_results ( $has_results ): $scan_path_log\n",3,"/tmp/net_scan.log");
}

if ( !$has_results ){ 
    echo "<div style='color:red; margin:auto; text-align: center;'>"._("Scan aborted")."</div>\n";
}
                                       
    ?>

    <script type="text/javascript">
        setIframeHeight('process');
        $('.loading_nmap').remove();

        parent.$('#scan_button').removeAttr('disabled');
        parent.$('#scan_button').removeClass();
        parent.$('#scan_button').addClass('button');
    </script>

</div>

</body>
</html>


