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
* - valid_value()
* - submit()
*/
if ($_GET["section"] == "vulnerabilities"){ 
	header("Location:../vulnmeter/webconfig.php?nohmenu=1");
}
elseif ($_GET["section"] == "hids"){ 
	header("Location:../ossec/config.php?nohmenu=1");
}
elseif ($_GET["section"] == "wids"){ 
	header("Location:../wireless/setup.php?nohmenu=1");
}
elseif ($_GET["section"] == "assetdiscovery"){ 
	header("Location:../net/assetdiscovery.php?nohmenu=1");
}


require_once 'classes/Session.inc';
require_once 'classes/Sensor.inc';
//Session::logcheck("MenuConfiguration", "ConfigurationMain");
require_once 'ossim_conf.inc';
require_once 'classes/Security.inc';
require_once 'classes/Util.inc';
require_once 'classes/Notification.inc';
require_once 'languages.inc';

if (!Session::am_i_admin()) {
	echo ossim_error(_("You don't have permission to see this page"));
	exit();
}

$tz = Util::get_timezone();

$ossim_conf     = $GLOBALS["CONF"];

$cloud_instance = ( $ossim_conf->get_conf("cloud_instance", FALSE) == 1 )    ? true : false;

$flag_status    = $_GET['status'];
$error_string   = $_GET['error'];
$warning_string = $_GET['warning'];

ossim_valid($flag_status, OSS_DIGIT, OSS_NULLABLE, 'illegal:' . _("flag status"));
ossim_valid($error_string, OSS_LETTER, OSS_DIGIT, OSS_NULLABLE, OSS_SPACE, OSS_COLON, OSS_SCORE, '<>\/', 'illegal:' . _("error string"));
ossim_valid($warning_string, OSS_LETTER, OSS_DIGIT, OSS_NULLABLE, OSS_SPACE, OSS_COLON, OSS_SCORE, '\.,<>\/\(\)', 'illegal:' . _("warning string"));

if (ossim_error()) {
    die(ossim_error());
}

if ( $flag_status == 1 ){ 
	$status_message = _("Configuration successfully updated");
}
elseif( $flag_status == 2 ){
	$status_message =  $error_string;
}

//Connect to db */
$db    = new ossim_db();
$conn  = $db->connect();


//Sensor List
$all_sensors = Sensor::get_all($conn, "ORDER BY name ASC");

$sensor_list = array("0" => "First available sensor");

foreach ($all_sensors as $sensor){
	$sensor_list[$sensor->get_name()] = $sensor->get_name()." [".$sensor->get_ip()."]";
}	


if ( Session::is_pro() )
{
    //menu template list
    list($templates, $num_templates) = Session::get_templates($conn);

    if ( count($templates) < 1 ){ 
        $templates[0] = array("id"=>'',"name"=>'- No templates found -'); 
    }

    $menus = array();

    foreach($templates as $template){ 
        $menus[$template['id']] = $template['name'];
    } 
        
    //Entity list
	$entities_all = Acl::get_entities_to_assign($conn);	
	
	if ( is_array($entities_all) && count($entities_all) > 0 )
	{
		foreach ($entities_all as $k => $v )
		{
			if( !Acl::is_logical_entity($conn, $k) ){
				$entities[$k] = $v;
			}
		}
	}
	else{
		$entities[''] = '- '._("No entities found").' -';	
	}

	asort($entities);
}

$open_threat_exchange_last = $conf->get_conf("open_threat_exchange_last", FALSE);

$CONFIG = array(
    "AlienVault Server" => array(
        "title" => gettext("AlienVault Server") ,
        "desc" => gettext("Configure AlienVault Server capabilities") ,
        "advanced" => 1,
    	"section" => "siem,logger,directives",
        "conf" => array(
            /*"server_address" => array(
                "type" => "text",
                "help" => gettext("Server IP") ,
                "desc" => gettext("Server Address (it's usually 127.0.0.1)") ,
                "advanced" => 1
            ) ,
            "server_port" => array(
                "type" => "text",
                "help" => gettext("Port number") ,
                "desc" => gettext("Server Port (default:40001)") ,
                "advanced" => 1
            ) ,
			"server_sim" => array(
                "type" => array(
                    "yes" => _("Yes") ,
                    "no" => _("No")
                ) ,
				"onchange" => "tsim(this.value)" ,
                "help" => gettext("SIEM") ,
                "desc" => "<font style='text-decoration:underline'>".gettext("SIEM")."</font>" ,
                "advanced" => 1
            ) ,
			"server_qualify" => array(
                "type" => array(
                    "yes" => _("Yes") ,
                    "no" => _("No")
                ) ,
				"id" => "qualify_select",
                "help" => gettext("Risk Assessment") ,
                "desc" => gettext("Risk Assessment") ,
                "advanced" => 1
            ) ,
			"server_correlate" => array(
                "type" => array(
                    "yes" => _("Yes") ,
                    "no" => _("No")
                ) ,
				"id" => "correlate_select",
                "help" => gettext("Logical Correlation") ,
                "desc" => gettext("Logical Correlation") ,
                "advanced" => 1 ,
                "section" => "directives"
            ) ,
			"server_cross_correlate" => array(
                "type" => array(
                    "yes" => _("Yes") ,
                    "no" => _("No")
                ) ,
				"id" => "cross_correlate_select",
                "help" => gettext("Cross-correlation") ,
                "desc" => gettext("Cross-correlation") ,
                "advanced" => 1 ,
                "section" => "directives"
            ) ,
            "frameworkd_postcorrelationmanager" => array(
                "type" => array(
                    "1" => _("Yes") ,
                    "0" => _("No")
                ) ,
				"id" => "frameworkd_postcorrelationmanager",
                "help" => gettext("Enable/Disable Post-correlation rules") ,
                "desc" => gettext("Post-correlation") ,
                "advanced" => 1 ,
                "section" => "directives"
            ) ,
			"server_store" => array(
                "type" => array(
                    "yes" => _("Yes") ,
                    "no" => _("No")
                ) ,
				"id" => "store_select",
                "help" => gettext("This defines the default policy behavior for this Server. If this is set to NO, the default behavior will be to not retain messages in the local MySQL DB. However, individual policies can override this and cause events to be retained locally.") ,
                "desc" => gettext("SQL Storage") ,
                "advanced" => 1
            ) ,
			"server_sem" => array(
                "type" => array(
                    "yes" => _("Yes") ,
                    "no"  => _("No")
                ) ,
				"onchange" => "tsem(this.value)" ,
                "help" => gettext("This defines the default policy behavior for the Forensic Logger. If this is set to NO, the default behavior will be to not log messages in the local Forensic Logger. However, individual policies can override this and cause logs to be written locally.") ,
                "desc" => "<font style='text-decoration:underline'>".gettext("Logger")."</font>" ,
                "advanced" => 1,
                "section" => "logger",
				"disabled" => (Session::is_pro()) ? 0 : 1
            ) ,
			"server_sign" => array(
                "type" => array(
                    "yes" => _("Line") ,
                    "no" => _("Block")
                ) ,
				"id" => "sign_select",
                "help" => gettext("Sign") ,
                "desc" => gettext("Sign") ,
                "advanced" => 1,
				"disabled" => (Session::is_pro()) ? 0 : 1
            ) ,
			"server_forward_alarm" => array(
                "type" => array(
                    "yes" => _("Yes") ,
                    "no" => _("No")
                ) ,
				"id" => "forward_alarm_select",
                "help" => gettext("Alarms forwarding") ,
                "desc" => gettext("Alarms forwarding") ,
                "advanced" => 1,
				"disabled" => (Session::is_pro()) ? 0 : 1
            ) ,
			"server_forward_event" => array(
                "type" => array(
                    "yes" => _("Yes") ,
                    "no" => _("No")
                ) ,
				"id" => "forward_event_select",
                "help" => gettext("Events forwarding") ,
                "desc" => gettext("Events forwarding") ,
                "advanced" => 1,
				"disabled" => (Session::is_pro()) ? 0 : 1
            ) ,*/
			"server_alarms_to_syslog" => array(
                "type" => array(
                    "yes" => _("Yes") ,
                    "no" => _("No")
                ) ,
				"id" => "alarms_to_syslog_select",
                "help" => (Session::is_pro()) ? gettext("Alarms to syslog") : _("Only Available when using Alienvault Unified SIEM"),
                "desc" => gettext("Alarms to syslog") ,
                "advanced" => 1,
				"disabled" => (Session::is_pro()) ? 0 : 1
            ) ,
			/*
			"server_remote_logger" => array(
                "type" => array(
                    "yes" => _("Yes") ,
                    "no" => _("No")
                ) ,
                "help" => (Session::is_pro()) ? gettext("OSSIM Remote Log console") : _("Only Available when using Alienvault Unified SIEM"),
                "desc" => gettext("Remote Logger console") ,
                "advanced" => 1,
                "section" => "logger",
				"disabled" => (Session::is_pro()) ? 0 : 1
            ) ,
			"server_remote_logger_user" => array(
                "type" => "text",
                "help" => gettext("OSSIM Remote Logger console user") ,
                "desc" => gettext("Remote Logger console user") ,
                "advanced" => 1,
            	"section" => "logger",
				"disabled" => (Session::is_pro()) ? 0 : 1
            ) ,
			"server_remote_logger_pass" => array(
                "type" => "password",
                "help" => gettext("OSSIM Remote Logger console password") ,
                "desc" => gettext("Remote Logger console password") ,
                "advanced" => 1,
            	"section" => "logger",
				"disabled" => (Session::is_pro()) ? 0 : 1
            ) ,
			"server_remote_logger_ossim_url" => array(
                "type" => "text",
                "help" => gettext("OSSIM Remote Logger console Url") ,
                "desc" => gettext("Remote Logger console Url") ,
                "advanced" => 1,
            	"section" => "logger",
				"disabled" => (Session::is_pro()) ? 0 : 1
            ) ,*/
            "server_logger_if_priority" => array(
                "type" => array(
                    "0" => 0,
                    "1" => 1,
            		"2" => 2,
            		"3" => 3,
            		"4" => 4,
            		"5" => 5
                ) ,
                "help" => gettext("Store in SIEM if event's priority >= this value")."<br>".gettext("Requires /etc/init.d/ossim-server restart") ,
                "desc" => gettext("Security Events process priority threshold") ,
                "advanced" => 1,
                "section" => "logger,siem",
				"disabled" => (Session::is_pro()) ? 0 : 1
            ) ,
            "databases_link" => array(
            	"type" => "link",
            	"help" => gettext("Define databases") ,
                "desc" =>  gettext("Define Security Events databases"),
            	"value"=> "<a target='".(($section != "") ? "_parent" : "topmenu")."' href='../top.php?hmenu=".md5("Configuration")."&smenu=".md5("SIEM Components")."&url=".urlencode("server/dbs.php?hmenu=SIEM+Components&smenu=DBs")."'>".gettext("Click here")."</a>",
                "advanced" => 1,
                "section" => "siem,logger",
				"disabled" => (Session::is_pro()) ? 0 : 1
            )
        )
    ) ,
    "Solera" => array(
        "title" => gettext("Solera") ,
        "desc" => gettext("Integration into the Solera DeepSee forensic suite") ,
        "advanced" => 1,
        "conf" => array(
            "solera_enable" => array(
                "type" => array(
                    "0" => gettext("No") ,
                    "1" => gettext("Yes")
                ) ,
                "help" => "" ,
                "desc" => gettext("Enable Solera integration") ,
                "advanced" => 1
            ),
            "solera_host" => array(
                "type" => "text",
                "help" => gettext("Solera API host. IP or FQDN") ,
                "desc" => gettext("Solera API host") ,
                "advanced" => 1,
            ),
            "solera_port" => array(
                "type" => "text",
                "help" => gettext("Solera API port") ,
                "desc" => gettext("Solera API port") ,
                "advanced" => 1,
            ),            
            "solera_user" => array(
                "type" => "text",
                "help" => gettext("Solera API user") ,
                "desc" => gettext("Solera API user") ,
                "advanced" => 1,
            ),
            "solera_pass" => array(
                "type" => "password",
                "help" => gettext("Solera API password") ,
                "desc" => gettext("Solera API password") ,
                "advanced" => 1,
            )
        )
    ),  
    "Ossim Framework" => array(
        "title" => gettext("Ossim Framework") ,
        "desc" => gettext("PHP Configuration (graphs, acls, database api) and links to other applications") ,
        "advanced" => 1,
    	"section" => "alarms",
        "conf" => array(
            /*"ossim_link" => array(
                "type" => "text",
                "help" => gettext("Ossim web link. Usually located under /ossim/") ,
                "desc" => gettext("Ossim Link") ,
                "advanced" => 1
            ) ,
            "adodb_path" => array(
                "type" => "text",
                "help" => gettext("ADODB Library path. PHP database extraction library.") ,
                "desc" => gettext("ADODB Path") ,
                "advanced" => 1
            ) ,
            "jpgraph_path" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("JPGraph Path") ,
                "advanced" => 1
            ) ,
            "fpdf_path" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("FreePDF Path") ,
                "advanced" => 1
            ) ,
            "xajax_php_path" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("XAJAX PHP Path") ,
                "advanced" => 1
            ) ,
            "xajax_js_path" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("XAJAX JS Path") ,
                "advanced" => 1
            ) ,
            "report_graph_type" => array(
                "type" => array(
                    "images" => gettext("Images (php jpgraph)") ,
                    "applets" => gettext("Applets (jfreechart)")
                ) ,
                "help" => "" ,
                "desc" => gettext("Graph Type") ,
                "advanced" => 1
            ) ,
            "use_svg_graphics" => array(
                "type" => array(
                    "0" => gettext("No") ,
                    "1" => gettext("Yes (Need SVG plugin)")
                ) ,
                "help" => "" ,
                "desc" => gettext("Use SVG Graphics") ,
                "advanced" => 1
            ) ,*/
            "use_resolv" => array(
                "type" => array(
                    "0" => gettext("No") ,
                    "1" => gettext("Yes")
                ) ,
                "help" => "" ,
                "desc" => gettext("Resolve IPs") ,
                "section" => "alarms",
                "advanced" => 1
            ) ,
            "nfsen_in_frame" => array(
                "type"  => array(
                    "0" => gettext("No") ,
                    "1" => gettext("Yes")
                ) ,
                "help"  => "",
                "desc"  => gettext("Open Remote NFsen in the same frame") ,
                "advanced" => 1
            ) ,
            "ntop_link" => array(
                "type"  => $sensor_list,
                "help"  => "" ,
                "desc"  => gettext("Default Ntop Sensor") ,
                "advanced" => 1
            ) ,/*
            "nagios_link" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("Default Nagios Link") ,
                "advanced" => 1
            ) ,
            "nagios_cfgs" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("Nagios Configuration file Path") ,
                "advanced" => 1
            ) ,
            "nagios_reload_cmd" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("Nagios reload command") ,
                "advanced" => 1
            ) ,
            /*"glpi_link" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("GLPI Link") ,
                "advanced" => 1
            ) ,
            "ocs_link" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("OCS Link") ,
                "advanced" => 1
            ) ,
            /*"ovcp_link" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("OVCP Link") ,
                "advanced" => 1
            ) ,
            "use_ntop_rewrite" => array(
                "type" => array(
                    "0" => gettext("No") ,
                    "1" => gettext("Yes")
                ) ,
                "help" => "" ,
                "desc" => gettext("Apache-rewrite ntop") ,
                "advanced" => 1
            ) ,
            "use_munin" => array(
                "type" => array(
                    "0" => gettext("No") ,
                    "1" => gettext("Yes")
                ) ,
                "help" => "" ,
                "desc" => gettext("Enable Munin") ,
                "advanced" => 1
            ) ,
            /*"munin_link" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("Munin Link") ,
                "advanced" => 1
            ) ,*/
            "md5_salt" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("MD5 salt for passwords") ,
                "advanced" => 1
            )
        )
    ) ,
    "Ossim FrameworkD" => array(
        "title" => gettext("Ossim Framework Daemon") ,
        "desc" => gettext("Configure the frameworkd capabilities") ,
        "advanced" => 1,
        "conf" => array(
            "frameworkd_address" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("Frameworkd Address") ,
                "advanced" => 1
            )/*  ,
            "frameworkd_port" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("Frameworkd Port") ,
                "advanced" => 1
            ),
            "frameworkd_dir" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("Frameworkd Directory") ,
                "advanced" => 1
            ) ,
            "frameworkd_controlpanelrrd" => array(
                "type" => array(
                    "0" => gettext("Disabled") ,
                    "1" => gettext("Enabled")
                ) ,
                "help" => "" ,
                "desc" => gettext("Enable ControlPanelRRD") ,
                "advanced" => 1
            ) ,
            "frameworkd_acidcache" => array(
                "type" => array(
                    "0" => gettext("Disabled") ,
                    "1" => gettext("Enabled")
                ) ,
                "help" => "" ,
                "desc" => gettext("Enable AcidCache") ,
                "advanced" => 1
            ) ,
            "frameworkd_donagios" => array(
                "type" => array(
                    "0" => gettext("Disabled") ,
                    "1" => gettext("Enabled")
                ) ,
                "help" => "" ,
                "desc" => gettext("Enable DoNagios") ,
                "advanced" => 1
            ) ,
            "frameworkd_alarmincidentgeneration" => array(
                "type" => array(
                    "0" => gettext("Disabled") ,
                    "1" => gettext("Enabled")
                ) ,
                "help" => "" ,
                "desc" => gettext("Enable AlarmTicketGeneration") ,
                "advanced" => 1
            ) ,
            "frameworkd_optimizedb" => array(
                "type" => array(
                    "0" => gettext("Disabled") ,
                    "1" => gettext("Enabled")
                ) ,
                "help" => "" ,
                "desc" => gettext("Enable DB Optimizations") ,
                "advanced" => 1
            ) ,
            "frameworkd_listener" => array(
                "type" => array(
                    "0" => gettext("Disabled") ,
                    "1" => gettext("Enabled")
                ) ,
                "help" => "" ,
                "desc" => gettext("Enable Listener") ,
                "advanced" => 1
            ) ,
            "frameworkd_scheduler" => array(
                "type" => array(
                    "0" => gettext("Disabled") ,
                    "1" => gettext("Enabled")
                ) ,
                "help" => "" ,
                "desc" => gettext("Enable Scheduler") ,
                "advanced" => 1
            ) ,/*
            "frameworkd_soc" => array(
                "type" => array(
                    "0" => gettext("Disabled") ,
                    "1" => gettext("Enabled")
                ) ,
                "help" => "" ,
                "desc" => gettext("Enable SOC functionality") ,
                "advanced" => 1
            ) ,
            "frameworkd_businessprocesses" => array(
                "type" => array(
                    "0" => gettext("Disabled") ,
                    "1" => gettext("Enabled")
                ) ,
                "help" => "" ,
                "desc" => gettext("Enable BusinesProcesses") ,
                "advanced" => 1
            ) ,
            "frameworkd_eventstats" => array(
                "type" => array(
                    "0" => gettext("Disabled") ,
                    "1" => gettext("Enabled")
                ) ,
                "help" => "" ,
                "desc" => gettext("Enable EventStats") ,
                "advanced" => 1
            ) ,
            "frameworkd_backup" => array(
                "type" => array(
                    "0" => gettext("Disabled") ,
                    "1" => gettext("Enabled")
                ) ,
                "help" => "" ,
                "desc" => gettext("Enable Backups") ,
                "advanced" => 1
            ) ,
            "frameworkd_alarmgroup" => array(
                "type" => array(
                    "0" => gettext("Disabled") ,
                    "1" => gettext("Enabled")
                ) ,
                "help" => "" ,
                "desc" => gettext("Enable Alarm Grouping") ,
                "advanced" => 1
            )*/
        )
    ) ,
    "Snort" => array(
        "title" => gettext("Snort") ,
        "desc"  => gettext("Snort database and path configuration") ,
        "advanced" => 1,
        "conf" => array(
            "snort_path" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("Snort location") ,
                "disabled" => 1,
                "advanced" => 1
            ) ,
            "snort_rules_path" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("Snort rule location") ,
                "disabled" => 1,
                "advanced" => 1
            ) ,
            /*
            "snort_type" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("Snort DB Type") ,
                "advanced" => 1
            ) , */
            "snort_base" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("Snort DB Name") ,
                "disabled" => 1,
                "advanced" => 1
            ) ,
            "snort_user" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("Snort DB User") ,
                "disabled" => 1,
                "advanced" => 1
            ) ,
            "snort_pass" => array(
                "type" => "password",
                "help" => "" ,
                "desc" => gettext("Snort DB Password") ,
                "disabled" => 1,
                "advanced" => 1
            ) ,
            "snort_host" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("Snort DB Host") ,
                "disabled" => 1,
                "advanced" => 1
            ) ,
            "snort_port" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("Snort DB Port") ,
                "disabled" => 1,
                "advanced" => 1
            )
        )
    ) ,
    "Osvdb" => array(
        "title" => gettext("OSVDB") ,
        "desc" => gettext("Open source vulnerability database configuration") ,
        "advanced" => 1,
        "conf" => array(
	    /*
            "osvdb_type" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("OSVDB DB Type") ,
                "advanced" => 1
            ) ,*/
            "osvdb_base" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("OSVDB DB Name") ,
                "advanced" => 1
            ) ,
            "osvdb_user" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("OSVDB DB User") ,
                "advanced" => 1
            ) ,
            "osvdb_pass" => array(
                "type" => "password",
                "help" => "" ,
                "desc" => gettext("OSVDB DB Password") ,
                "advanced" => 1
            ) ,
            "osvdb_host" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("OSVDB DB Host") ,
                "advanced" => 1
            )
        )
    ) ,
    "Metrics" => array(
        "title" => gettext("Metrics") ,
        "desc" => gettext("Configure metric settings") ,
        "advanced" => 0,
    	"section" => "metrics",
        "conf" => array(
            "recovery" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("Recovery Ratio") ,
                "advanced" => 0 ,
    			"section" => "metrics"
            ) ,
            "threshold" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("Global Threshold") ,
                "advanced" => 0 ,
            	"section" => "metrics"
            ) ,
            "def_asset" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("Default Asset value") ,
                "advanced" => 0 ,
            	"section" => "metrics"
            )
        )
    ) ,
	
	/*
    "Executive Panel" => array(
        "title" => gettext("Executive Panel") ,
        "desc" => gettext("Configure panel settings") ,
        "advanced" => 1,
    	"section" => "panel",
        "conf" => array(
            "panel_plugins_dir" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("Executive Panel plugin Directory") ,
                "advanced" => 1 ,
    			"section" => "panel"
            ) ,
            "panel_configs_dir" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("Executive Panel Config Directory") ,
                "advanced" => 1 ,
            	"section" => "panel"
            )
        )
    ) ,
    "ACLs" => array(
        "title" => gettext("ACL phpGACL configuration") ,
        "desc" => gettext("Access control list database configuration") ,
        "advanced" => 1,
        "conf" => array(
            "phpgacl_path" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("PHPGacl Path") ,
                "advanced" => 1
            ) ,
            "phpgacl_type" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("PHPGacl DB Type") ,
                "advanced" => 1
            ) ,
            "phpgacl_host" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("PHPGacl DB Host") ,
                "advanced" => 1
            ) ,
            "phpgacl_base" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("PHPGacl DB Name") ,
                "advanced" => 1
            ) ,
            "phpgacl_user" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("PHPGacl DB User") ,
                "advanced" => 1
            ) ,
            "phpgacl_pass" => array(
                "type" => "password",
                "help" => "" ,
                "desc" => gettext("PHPGacl DB Password") ,
                "advanced" => 1
            )
        )
    ) ,
    "RRD" => array(
        "title" => gettext("RRD") ,
        "desc" => gettext("RRD Configuration (graphing)") ,
        "advanced" => 1,
        "conf" => array(
            "graph_link" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("RRD Draw graph link") ,
                "advanced" => 1
            ) ,
            "rrdtool_path" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("RRDTool Path") ,
                "disabled" => 1,
                "advanced" => 1
            ) ,
            "rrdtool_lib_path" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("RRDTool Lib Path") ,
                "advanced" => 1
            ) ,
            "mrtg_path" => array(
                "type" => "text",
                "help" => gettext("Unused.") ,
                "desc" => gettext("MRTG Path") ,
                "advanced" => 1
            ) ,
            "mrtg_rrd_files_path" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("MRTG RRD Files") ,
                "advanced" => 1
            ) ,
            "rrdpath_host" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("Host Qualification RRD Path") ,
                "advanced" => 1
            ) ,
            "rrdpath_net" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("Net Qualification RRD Path") ,
                "advanced" => 1
            ) ,
            "rrdpath_global" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("Global Qualification RRD Path") ,
                "advanced" => 1
            ) ,
            "rrdpath_level" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("Service level RRD Path") ,
                "advanced" => 1
            ) ,
            "rrdpath_incidents" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("Ticket trend RRD Path") ,
                "advanced" => 1
            ) ,
            "rrdpath_bps" => array(
                "type" => "text",
                "help" => gettext("business processes rrd directory") ,
                "desc" => gettext("BPs RRD Path") ,
                "advanced" => 1
            ) ,
            "rrdpath_ntop" => array(
                "type" => "text",
                "help" => gettext("Defaults to /var/lib/ntop/rrd/") ,
                "desc" => gettext("Ntop RRD Path") ,
                "advanced" => 1
            ) ,
            "rrdpath_stats" => array(
                "type" => "text",
                "help" => gettext("Event Stats RRD directory") ,
                "desc" => gettext("EventStats RRD Path") ,
                "advanced" => 1
            ) ,
            "font_path" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("TTF Location") ,
                "advanced" => 1
            )
        )
    ) ,*/
    "Backup" => array(
        "title" => gettext("Backup") ,
        "desc" => gettext("Backup configuration: backup database, directory, interval") ,
        "advanced" => 0,
    	"section" => "siem",
        "conf" => array(
	     /*
            "backup_type" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("Backup DB Type") ,
                "advanced" => 1
            ) , */
            "backup_base" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("Backup DB Name") ,
                "advanced" => 1
            ) ,
            "backup_user" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("Backup DB User") ,
                "advanced" => 1
            ) ,
            "backup_pass" => array(
                "type" => "password",
                "help" => "" ,
                "desc" => gettext("Backup DB Password") ,
                "advanced" => 1
            ) ,
            "backup_host" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("Backup DB Host") ,
                "advanced" => 1
            ) ,
            "backup_port" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("Backup DB Port") ,
                "advanced" => 1
            ) ,
            "backup_store" => array(
                "type" => array(
                    "0" => gettext("No") ,
                    "1" => gettext("Yes")
                ) ,
                "help" => gettext("Enable/Disable SIEM Events database backup. The events out of active window will be stored in backup files") ,
                "desc" => gettext("Enable SIEM database backup") ,
                "advanced" => 1
            ) ,
            "backup_dir" => array(
                "type" => "text",
                "help" => gettext("Defaults to /var/lib/ossim/backup/") ,
                "desc" => gettext("Backup File Directory") ,
                "advanced" => 1
            ) ,
            "frameworkd_backup_storage_days_lifetime" => array(
                "type" => "text",
                "help" => gettext("Number of days Siem events are stored in hard-disk") ,
                "desc" => gettext("Number of Backup files to keep in the filesystem") ,
            	"section" => "siem",
                "advanced" => 0
            ) ,
            "backup_day" => array(
                "type" => "text",
                "help" => gettext("Number of days Siem events are stored in SQL Database (0 value means no backup)") ,
                "desc" => gettext("Events to keep in the Database (Number of days)") ,
            	"section" => "siem",
                "advanced" => 0
            ) ,
            "backup_events" => array(
                "type" => "text",
                "help" => gettext("Maximum number of events stored in SQL Database (0 value does no limit)") ,
                "desc" => gettext("Events to keep in the Database (Number of events)") ,
            	"section" => "siem",
                "advanced" => 0
            ) ,            
            "backup_netflow" => array(
                "type" => "text",
                "help" => gettext("Number of days to store flows on netflows for") ,
                "desc" => gettext("Active Netflow Window") ,
                "advanced" => 0
            ) ,
            "alarms_expire" => array(
                "type" => array(
                    "yes" => _("Yes") ,
                    "no"  => _("No")
                ) ,
                "help" => gettext("Keep alarms on database or expire by Lifetime value") ,
                "desc" => gettext("Alarms Expire") ,
            	"onchange" => "change_alarms_lifetime(this.value)" ,
				"value" => ($conf->get_conf("alarms_lifetime", FALSE) > 0) ? "yes" : "no" ,
                "advanced" => 0
            ) ,
            "alarms_lifetime" => array(
                "type" => "text",
            	"id"   => "alarms_lifetime",
                "help" => gettext("Number of days to keep alarms for (0 never expires)") ,
                "desc" => gettext("Alarms Lifetime") ,
            	"style" => ($conf->get_conf("alarms_lifetime", FALSE) > 0) ? "" : "color:gray" ,
                "advanced" => 0
            )
        )
    ) ,
    "Vulnerability Scanner" => array(
        "title" => gettext("Vulnerability Scanner") ,
        "desc" => gettext("Vulnerability Scanner configuration") ,
        "advanced" => 0,
    	"section" => "vulnerabilities",
        "conf" => array(
            "scanner_type" => array(
                "type" => array(
                    "openvas3omp" => gettext("OpenVAS 4.x (OpenVAS Manager)") ,
                    "openvas3" => gettext("OpenVAS 3.x") ,
                    "openvas2" => gettext("OpenVAS 2.x") ,
                    "nessus2" => gettext("Nessus 2.x") ,
                    "nessus3" => gettext("Nessus 3.x") ,
                    "nessus4" => gettext("Nessus 4.x") ,
                    "vcad" => gettext("VCAD")
                ) ,
                "help" => gettext("Vulnerability scanner used. OpenVAS is used by default.") ,
                "desc" => gettext("Vulnerability Scanner") ,
                "advanced" => 1 ,
                "section" => "vulnerabilities"
            ) ,
            "nessus_user" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("Scanner Login") ,
                "advanced" => 1 ,
            	"section" => "vulnerabilities"
            ) ,
            "nessus_pass" => array(
                "type" => "password",
                "help" => "" ,
                "desc" => gettext("Scanner Password") , 
                "advanced" => 1 ,
            	"section" => "vulnerabilities"
            ) ,
            "nessus_host" => array(
                "type" => "text",
                "help" => gettext("Only for non distributed scans") ,
                "desc" => gettext("Scanner host") ,
                "advanced" => 1 ,
            	"section" => "vulnerabilities"
            ) ,
            "nessus_port" => array(
                "type" => "text",
                "help" => gettext("Defaults to port 1241 on Nessus, 9390 on OpenVAS") ,
                "desc" => gettext("Scanner port") ,
                "advanced" => 1 ,
            	"section" => "vulnerabilities"
            ) ,
            "nessus_path" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("Scanner Binary location") ,
                "advanced" => 1 ,
            	"section" => "vulnerabilities"
            ) ,
            "nessus_updater_path" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("Scanner Updater location") , 
                "advanced" => 1 ,
            	"section" => "vulnerabilities"
            ) ,
            "nessus_rpt_path" => array(
                "type" => "text",
                "help" => gettext("Where will scanning results be located") ,
                "desc" => gettext("Scan output path") ,
                "advanced" => 1 ,
            	"section" => "vulnerabilities"
            ) ,
            /*"nessusrc_path" => array(
                "type" => "text",
                "help" => gettext("Configuration (.rc) file") ,
                "desc" => gettext("Configuration file location") ,
                "advanced" => 0
            ) ,
            "nessus_distributed" => array(
                "type" => array(
                    "0" => gettext("No") ,
                    "1" => gettext("Yes")
                ) ,
                "help" => gettext("Obsolete, distributed is very recommended even if you only got one sensor.") ,
                "desc" => gettext("Distributed Scanning") ,
                "advanced" => 1 ,
                "section" => "vulnerabilities"
            ) ,*/
            "nessus_pre_scan_locally" => array(
                "type" => array(
                    "0" => gettext("No") ,
                    "1" => gettext("Yes")
                ) ,
                "help" => gettext("do not pre-scan from scanning sensor") ,
                "desc" => gettext("Enable Pre-Scan locally") ,
                "advanced" => 1 ,
                "section" => "vulnerabilities"
            ) ,
            "vulnerability_incident_threshold" => array(
                "type" => array(
                    "0" => "0",
                    "1" => "1",
                    "2" => "2",
                    "3" => "3",
                    "4" => "4",
                    "5" => "5",
                    "6" => "6",
                    "7" => "7",
                    "8" => "8",
                    "9" => "9",
                    "11" => _("Disabled")
                ) ,
                "help" => gettext("Any vulnerability with a higher risk level than this value will get inserted automatically into DB.") ,
                "desc" => gettext("Vulnerability Ticket Threshold") ,
                "advanced" => 0 ,
                "section" => "vulnerabilities"
            )
        )
    ) ,/*
    "Acid/Base" => array(
        "title" => gettext("ACID/BASE") ,
        "desc" => gettext("Acid and/or Base configuration") ,
        "advanced" => 1,
        "conf" => array(
            "event_viewer" => array(
                "type" => array(
                    "acid" => gettext("Acid") ,
                    "base" => gettext("Base")
                ) ,
                "help" => gettext("Choose your event viewer") ,
                "desc" => gettext("Event Viewer") ,
                "advanced" => 1
            ) ,
            "acid_link" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("Event viewer link") ,
                "advanced" => 1
            ) ,
            "acid_path" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("Event viewer php path") ,
                "advanced" => 1
            ) ,
            "acid_user" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("Frontend login for event viewer") ,
                "advanced" => 1
            ) ,
            "acid_pass" => array(
                "type" => "password",
                "help" => "" ,
                "desc" => gettext("Frontend password for event viewer") ,
                "advanced" => 1
            ) ,
            "ossim_web_user" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("OSSIM Web user") ,
                "advanced" => 1
            ) ,
            "ossim_web_pass" => array(
                "type" => "password",
                "help" => "" ,
                "desc" => gettext("OSSIM Web Password") ,
                "advanced" => 1
            )
        )
    ) ,
    "External Apps" => array(
        "title" => gettext("External applications") ,
        "desc" => gettext("Path to other applications") ,
        "advanced" => 1,
        "conf" => array(
            "nmap_path" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("NMap Binary Path") ,
                "advanced" => 1
            ) ,
            "p0f_path" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("P0f Binary Path") ,
                "advanced" => 1
            ) ,
            "arpwatch_path" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("Arpwatch Binary Path") ,
                "advanced" => 1
            ) ,
            "mail_path" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("Mail Binary Path") ,
                "advanced" => 1
            ) ,
            "touch_path" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("'touch' Binary Path") ,
                "advanced" => 1
            ) ,
            "wget_path" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("Wget Binary Path") ,
                "advanced" => 1
            ) ,
            "have_scanmap3d" => array(
                "type" => array(
                    "0" => gettext("No") ,
                    "1" => gettext("Yes")
                ) ,
                "help" => "" ,
                "desc" => gettext("Use Scanmap 3D") ,
                "advanced" => 0
            )
        )
    ) ,*/
    "User Log" => array(
        "title" => gettext("User activity") ,
        "desc" => gettext("User action logging") ,
        "advanced" => 0,
    	"section" => "userlog",
        "conf" => array(
            "session_timeout" => array(
                "type" => "text",
                "help" => gettext("Expired timeout for current session in minutes. (0=unlimited)") ,
                "desc" => gettext("Session Timeout (minutes)") ,
                "advanced" => 0 ,
    			"section" => "userlog"
            ),
            "user_life_time" => array(
                "type" => "text",
                "help" => gettext("Expired life time for current user in days. (0=never expires)") ,
                "desc" => gettext("User Life Time (days)") ,
                "advanced" => 0 ,
    			"section" => "userlog"
            ),
            "user_action_log" => array(
                "type" => array(
                    "0" => gettext("No") ,
                    "1" => gettext("Yes")
                ) ,
                "help" => "",
                "desc" => gettext("Enable User Log") ,
                "advanced" => 0 ,
                "section" => "userlog"
            ) ,
            "log_syslog" => array(
                "type" => array(
                    "0" => gettext("No") ,
                    "1" => gettext("Yes")
                ) ,
                "help" => "" ,
                "desc" => gettext("Log to syslog") ,
                "advanced" => 0 ,
                "section" => "userlog"
            ) ,
            "dashboard_refresh" => array(
                "type" => "text" ,
                "help" => gettext("0 = disable autorefresh") ,
                "desc" => gettext("Seconds to refresh Dashboard") ,
                "advanced" => 0 ,
                "section" => "userlog"
            )
        )
    ) ,
    /*
    "Event Viewer" => array(
        "title" => gettext("Real time event viewer") ,
        "desc" => gettext("Real time event viewer") ,
        "advanced" => 1,
        "conf" => array(
            "max_event_tmp" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("Event limit for real time event viewer") ,
                "advanced" => 1
            )
        )
    ) ,*/
    "Login" => array(
        "title" => gettext("Login methods/options") ,
        "desc" => gettext("Setup main login methods/options") ,
        "advanced" => 0,
    	"section" => "users",
        "conf" => array(
            "first_login" => array(
                "type" => array(
                    "yes" => _("Yes") ,
                    "no" => _("No")
                ) ,
                "help" => "",
                "desc" => gettext("Show welcome message at next login") ,
                "advanced" => 0 ,
                "section" => "users"
            ) ,
            "remote_key" => array(
                "type" => "password",
                "help" => _("To apply this change restart your session"),
                "desc" => gettext("Remote login key") ,
                "advanced" => 1 ,
                "section" => "users"
            ), 
            "login_enable_ldap" => array(
                "type" => array(
                    "yes" => _("Yes") ,
                    "no" => _("No")
                ) ,
                "help" => "",
                "desc" => gettext("Enable LDAP for login") ,
                "advanced" => 1 ,
                "section" => "users"
            ) ,
            "login_ldap_server" => array(
                "type" => "text",
                "help" => "Ldap server IP or host name",
                "desc" => gettext("Ldap server address") ,
                "advanced" => 1 ,
                "section" => "users"
            ) ,
            "login_ldap_port" => array(
                "type" => "text",
                "help" => "TCP port to connect Ldap server<br />By default the port is 389 or 639 if you use SSL",
                "id" => "ldap_port",
                "desc" => gettext("Ldap server port") ,
                "advanced" => 1 ,
                "section" => "users"
            ) ,
            "login_ldap_ssl" => array(
                "type" => array(
                    "yes" => _("Yes") ,
                    "no" => _("No")
                ) ,
                "help" => gettext("use Ldap server ssl?") ,
                "desc" => gettext("Ldap server ssl") ,
                "onchange" => "change_ldap_port(this.value)" ,
                "advanced" => 1 ,
                "section" => "users"
            ) ,
            "login_ldap_baseDN" => array(
                "type" => "text",
                "help" => "Example: dc=local,dc=domain,dc=net" ,
                "desc" => gettext("Ldap server baseDN") ,
                "advanced" => 1 ,
                "section" => "users"
            ) ,
            "login_ldap_filter_to_search" => array(
                "type" => "text",
                "help" => gettext("Filter to search the users for ossim in LDAP<br />Example for LDAP: (&(cn=%u)(objectClass=account)) <b>or</b> (uid=%u) <b>or</b> (&(cn=%u)(objectClass=OrganizationalPerson))<br />Example for AD: (&(sAMAccountName=%u)(objectCategory=person)) <b>or</b> (userPrincipalName=%u)<br />%u is the user") ,
                "desc" => gettext("Ldap server filter for LDAP users") ,
                "advanced" => 1 ,
                "section" => "users"
            ) ,
            "login_ldap_bindDN" => array(
                "type" => "text",
                "help" => gettext("Account to search the user in LDAP<br />Example: cn=admin,dc=local,dc=domain,dc=net") ,
                "desc" => gettext("Ldap bindDN") ,
                "advanced" => 1 ,
                "section" => "users"
            ) ,
            "login_ldap_valid_pass" => array(
                "type" => "password",
                "help" => gettext("Password of Ldap bindDN") ,
                "desc" => gettext("Ldap pasword for bindDN") ,
                "advanced" => 1 ,
                "section" => "users"
            ) ,
            "login_ldap_require_a_valid_ossim_user" => array(
                "type" => array(
                    "yes" => _("Yes") ,
                    "no" => _("No")
                ) ,
                "help" => "",
                "desc" => gettext("Require a valid ossim user for login?") ,
                "advanced" => 1 ,
                "onchange" => "change_ldap_need_user(this.value)" ,
                "section" => "users"
            ) ,
            "login_create_not_existing_user_entity" => array(
                "type" => $entities ,
                "help" => "",
                "id"   => "user_entity",
                "desc" => gettext("Entity for new user") ,
                "advanced" => 1 ,
                "section" => "users",
            ) ,
            "login_create_not_existing_user_menu" => array(
                "type" => $menus ,
                "help" => "",
                "id"   => "user_menu",
                "desc" => gettext("Menus for new user") ,
                "advanced" => 1 ,
                "section" => "users",
            )
        )
    ) ,
    "Passpolicy" => array(
        "title" => gettext("Password policy") ,
        "desc" => gettext("Setup login password policy options") ,
        "advanced" => 1,
        "section" => "users",
        "conf" => array(
			"pass_length_min" => array(
                "type" => "text",
                "help" => _("Number (default = 7)") ,
                "desc" => gettext("Minimum password length") ,
                "advanced" => 1 ,
                "section" => "users"
            ),
            "pass_length_max" => array(
                "type" => "text",
                "help" => _("Number (default = 32)") ,
                "desc" => gettext("Maximum password length") ,
                "advanced" => 1 ,
                "section" => "users"
            ),
            "pass_history" => array(
                "type" => "text",
                "help" => _("Number (default = 0) -> 0 disable") ,
                "desc" => gettext("Password history") ,
                "advanced" => 1 ,
                "section" => "users"
            ),
            "pass_complex" => array(
                "type" => array(
                    "yes" => _("Yes") ,
                    "no" => _("No")
                ) ,
                "help" => _("3 of these group of characters -> lowercase, uppercase, numbers, special characters") ,
                "desc" => gettext("Complexity") ,
                "advanced" => 1 ,
                "section" => "users"
            ),
        	"pass_expire_min" => array(
                "type" => "text",
                "help" => _("The minimum password lifetime prevents users from circumventing")."<br/>"._("the requirement to change passwords by doing five password changes<br> in a minute to return to the currently expiring password. (0 to disable) (default 0)") ,
                "desc" => gettext("Minimum password lifetime in minutes") ,
                "advanced" => 1 ,
                "section" => "users"
            ),
        	"pass_expire" => array(
                "type" => "text",
                "help" => _("After these days the login ask for new password. (0 to disable) (default 0)") ,
                "desc" => gettext("Maximum password lifetime in days") ,
                "advanced" => 1 ,
                "section" => "users"
            ),
			"failed_retries" => array(
                "type" => "text",
                "help" => _("Number of failed attempts prior to lockout") ,
                "desc" => gettext("Failed logon attempts") ,
                "advanced" => 1 ,
                "section" => "users"
            ),
			"unlock_user_interval" => array(
                "type" => "text",
                "help" => _("Account lockout duration in minutes (0 = never auto-unlock)") ,
                "desc" => gettext("Account lockout duration") ,
                "advanced" => 1 ,
                "section" => "users"
            )
        )
    ), /*
    "Updates" => array(
        "title" => gettext("Updates") ,
        "desc" => gettext("Configure updates") ,
        "advanced" => 0,
        "conf" => array(
            "update_checks_enable" => array(
                "type" => array(
                    "yes" => _("Yes") ,
                    "no" => _("No")
                ) ,
                "help" => gettext("The system will check once a day for updated packages, rules, directives, etc.")."<br/>"._("No system information will be sent, it just gets a file with dates and update messages using wget.") ,
                "desc" => gettext("Enable auto update-checking") ,
                "advanced" => 0
            ) ,
            "update_checks_use_proxy" => array(
                "type" => array(
                    "yes" => _("Yes") ,
                    "no" => _("No")
                ) ,
                "help" => "" ,
                "desc" => gettext("Use proxy for auto update-checking") ,
                "advanced" => 1
            ) ,
            "proxy_url" => array(
                "type" => "text",
                "help" => gettext("Enter the full path including a trailing slash, i.e., 'http://192.168.1.60:3128/'") ,
                "desc" => gettext("Proxy url") ,
                "advanced" => 1
            ) ,
            "proxy_user" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("Proxy User") ,
                "advanced" => 1
            ) ,
            "proxy_password" => array(
                "type" => "password",
                "help" => "" ,
                "desc" => gettext("Proxy Password") ,
                "advanced" => 1
            ) ,
            //"last_update" => array(
            //    "type" => "text",
            //    "help" => "" ,
            //    "desc" => gettext("Last update timestamp") ,
            //    "advanced" => 1
            //) ,
        )
    ) ,*/
    "IncidentGeneration" => array(
        "title" => gettext("Tickets") ,
        "desc" => gettext("Tickets parameters") ,
        "advanced" => 0,
    	"section" => "tickets,alarms",
        "conf" => array(
            "alarms_generate_incidents" => array(
                "type" => array(
                    "yes" => _("Yes"),
                    "no" => _("No")
                ) ,
                "help" => gettext("Enabling this option will lead to automatic ticket generation upong arrival of alarms.") ,
                "desc" => gettext("Open Tickets for new alarms automatically?") ,
                "section" => "tickets,alarms",
                "advanced" => 0
            ) ,
			"tickets_send_mail" => array(
                "type" => array(
                    "yes" => _("Yes"),
                    "no"  => _("No")
                ),
                "help" => "",
                "desc" => gettext("Send email notification"),
            	"section"  => "tickets",
                "advanced" => 0
            ) ,
            "tickets_max_days" => array(
                "type" => "text",
                "help" => "" ,
                "desc" => gettext("Maximum days for email notification") ,
                "advanced" => 0 ,
            	"section" => "tickets"
            )/*,
            "google_maps_key" => array(
                "type" => "textarea",
                "help" => gettext("http://code.google.com/apis/maps/signup.html") ,
                "desc" => gettext("Google Maps API Key") ,
            	"section" => "tickets",
                "advanced" => 0
            )*/
        )
    ) ,
    
    "OTX" => array(
        "title" => gettext("Open Threat Exchange") ,
        "desc" => gettext("Open Threat Exchange Configuration") ,
        "advanced" => 1,
    	"section" => "otx",
        "conf" => array(
            "open_threat_exchange" => array(
                "type" => array(
                    "yes" => _("Yes") ,
                    "no" => _("No")
                ) ,
                "help" => gettext("Send information about logs") ,
                "desc" => gettext("Contribute threat information to AlienVault OTX?") ,
                "section" => "otx",
                "onchange" => ($conf->get_conf("open_threat_exchange", FALSE) != "yes" && $conf->get_conf("open_threat_exchange_key", FALSE) == "") ? "if (this.value=='yes') document.location.href='../updates/otxform.php'; else document.location.href='../updates/otxform.php?join=2'" : "enable_disable(this.value, 'otx')",
                "advanced" => 1
            ),
            "open_threat_exchange_key" => array(
                "type" => "html",
                "classname" => "otx",
                "help" => gettext("OTX Key") ,
                "desc" => gettext("OTX Key") ,
            	"style" => ($conf->get_conf("open_threat_exchange", FALSE) == "yes") ? "" : "color:gray" ,
            	"value" => "<span class='otx' ".(($conf->get_conf("open_threat_exchange", FALSE) == "yes") ? "" : "style='color:gray'").">".$conf->get_conf("open_threat_exchange_key", FALSE)."</span>" ,
                "advanced" => 1
            ),
            "open_threat_exchange_last" => array(
                "type" => "html",
            	"classname" => "otx",
            	"help" => gettext("Last contribution to OTX") ,
            	"desc" => _("Last contribution to OTX"),
            	"value"=> "<span class='otx' ".(($conf->get_conf("open_threat_exchange", FALSE) != "yes") ? "style='color:gray'" : "").">".(($open_threat_exchange_last=="") ? "<span style='margin-right:15px;'>Never</span>" : "<b>".gmdate("Y-m-d H:i:s", strtotime($open_threat_exchange_last." GMT")+(3600*$tz))."</b>")."</span> <input type='button' value='Send now' onclick=\"GB_show('"._("Send now threat information")."','../updates/otxsend.php',450,'70%');\" class='otx button ".(($conf->get_conf("open_threat_exchange", FALSE) != "yes") ? "disabled' disabled='disabled'" : "'").">",
           		"style" => ($conf->get_conf("open_threat_exchange", FALSE) == "yes") ? "" : "color:gray" ,
                "advanced" => 1
            ),
            "open_threat_exchange_link" => array(
                "type" => "html",
            	"classname" => "otx",
            	"help" => gettext("Activation link to Labs") ,
            	"desc" => "Activation Link",
            	"value"=> "<a href='http://labs.alienvault.com/labs/index.php/activate-otx/?otxkey=".$conf->get_conf("open_threat_exchange_key", FALSE)."' target='_blank' class='otx' ".(($conf->get_conf("open_threat_exchange", FALSE) != "yes") ? "style='color:gray' disabled" : "").">http://labs.alienvault.com/labs/index.php/activate-otx/?<br>otxkey=".$conf->get_conf("open_threat_exchange_key", FALSE)."</a>",
            	"style" => ($conf->get_conf("open_threat_exchange", FALSE) == "yes") ? "" : "color:gray" ,
                "advanced" => 1
            )
        )
    ) ,

	/*"Action responses" => array(
        "title" => gettext("Action Responses") ,
        "desc" => gettext("Setup action responses") ,
        "advanced" => 1,
    	"section" => "actions",
        "conf" => array(
            "dc_ip" => array(
                "type" => "text",
                "help" => "",
                "desc" => gettext("Domain Controller IP") ,
    			"section" => "actions" ,
                "advanced" => 1
            ) ,
            "dc_acc" => array(
                "type" => "text",
                "help" => "",
                "desc" => gettext("Admin Account") ,
            	"section" => "actions" ,
                "advanced" => 1
            ) ,
            "dc_pass" => array(
                "type" => "password",
                "help" => "",
                "desc" => gettext("Password") ,
            	"section" => "actions" ,
                "advanced" => 1
            ) ,
            "snmp_comm" => array(
                "type" => "text",
                "help" => "",
                "desc" => gettext("Network SNMP Community") ,
            	"section" => "actions" ,
                "advanced" => 1
            )
		)
	),
	
	"Policy" => array(
        "title" => gettext("Policy") ,
        "desc" => gettext("Policy settings") ,
        "advanced" => 1,
        "conf" => array()
	),*/
    "Mail Server Configuration" => array(
        "title" => gettext("Mail Server Configuration") ,
        "desc" => gettext("Mail Server Configuration settings") ,
        "advanced" => 1,
        "conf" => array(
            "from" => array(
                "type" => "text",
                "help" => "",
                "desc" => gettext("From Address") ,
                "advanced" => 1
            ) ,
            "smtp_server_address" => array(
                "type" => "text",
                "help" => "",
                "desc" => gettext("SMTP Server IP Address") ,
                "advanced" => 1
            ) ,
            "smtp_port" => array(
                "type" => "text",
                "help" => "",
                "desc" => gettext("SMTP Server port") ,
                "advanced" => 1
            ) ,
            "smtp_user" => array(
                "type" => "text",
                "help" => "",
                "desc" => gettext("SMTP Username") ,
                "advanced" => 1
            ) ,
            "smtp_pass" => array(
                "type" => "password",
                "help" => "",
                "desc" => gettext("SMTP Password") ,
                "advanced" => 1
            ) ,
            "use_ssl" => array(
                "type" => array(
                    "yes" => _("Yes"),
                    "no" => _("No")
                ),
                "help" => "",
                "desc" => gettext("Use SSL Protocol") ,
                "advanced" => 1
            )
        )
    )
);

if( $cloud_instance && Session::am_i_admin() ) 
{

    $CONFIG["User Log"]["conf"]["cloud_max_users"] = array(
        "type" => "text",
        "help" => gettext("Maximum number of Users for cloud instance") ,
        "desc" => gettext("Maximum number of Users") ,
        "advanced" => 0 ,
        "section" => "userlog");
        
}

ksort($CONFIG);

function valid_value($key, $value, $numeric_values, $s_error)
{
    if (in_array($key, $numeric_values)) {
        if (!is_numeric($value)) 
		{
            require_once ("ossim_error.inc");
            $error = new OssimError();
			//$s_error = $error->get(_("NOT_NUMERIC"), $key);
			
			$error_code = ( empty($error->errors[_("NOT_NUMERIC")]) ) ? _("DEFAULT") : _("NOT_NUMERIC");
		        
			$s_error = "" . $error->errors["$error_code"]["short_descr"] . ": ";
			$s_error.= $error->errors["$error_code"]["long_descr"];
			$s_error = str_replace("%1%", $key, $s_error);
			
			// $error->display("NOT_NUMERIC", array(
                // $key
            // ), " /* Continue */ ");
			return false;
        }
    }
    return true;
}

function submit()
{
	?>
		<!-- submit -->
		<input type="button" class="button" style="display:none;margin-bottom:15px" id="enable_notifications" onclick="av_notification()" value=" <?php echo gettext("Enable Desktop Notifications"); ?> "/><br>
		<script type='text/javascript'>
		function RequestPermission(callback) { window.webkitNotifications.requestPermission(callback); }
		function av_notification() {
			if (window.webkitNotifications.checkPermission() > 0) {
    			RequestPermission(av_notification);
  			}
  			notificationw = window.webkitNotifications.createNotification('/ossim/statusbar/av_icon.png',"<?php echo Util::js_entities(html_entity_decode(_("Thank you"))) ?>","<?php echo Util::js_entities(html_entity_decode(_("Notifications enabled successfully")))?>");
  			notificationw.show();
  			setTimeout (function() { notificationw.cancel(); }, '10000');
		}
		if (window.webkitNotifications) { $('#enable_notifications').show(); }
		</script>
		<input type="submit" name="update" id="update" class="button" value=" <?php echo gettext("Update configuration"); ?> "/>
		<br/><br/>
		<!-- end sumbit -->
	<?php
}
if ( POST('update') )
{
    $numeric_values = array(
        "backup_events",
        "alarms_lifetime",
        "frameworkd_backup_storage_days_lifetime",
        "backup_netflow",
        "server_port",
        "use_resolv",
        "use_ntop_rewrite",
        "use_munin",
        "frameworkd_port",
        "frameworkd_controlpanelrrd",
        "frameworkd_donagios",
        "frameworkd_alarmincidentgeneration",
        "frameworkd_optimizedb",
        "frameworkd_listener",
        "frameworkd_scheduler",
        "frameworkd_businessprocesses",
        "frameworkd_eventstats",
        "frameworkd_backup",
        "frameworkd_alarmgroup",
        "snort_port",
        "recovery",
        "threshold",
        "backup_port",
        "backup_day",
        "nessus_port",
        "nessus_distributed",
        "vulnerability_incident_threshold",
        "have_scanmap3d",
        "user_action_log",
        "log_syslog",
        "pass_length_min",
        "pass_length_max",
        "pass_history",
        "pass_expire_min",
        "pass_expire",
        "failed_retries",
        "unlock_user_interval",
        "tickets_max_days",
        "smtp_port"
    );
        
    require_once 'classes/Config.inc';
    
	$config = new Config();
	
	$pass_fields = array();
		
	foreach ($CONFIG as $conf)
	{
		foreach ($conf['conf'] as $k => $v)
		{
			if ( $v['type'] == "password" ){
				$pass_fields[$k] = 1;
			}
		}
	}
	
	$flag_status    = 1;
	$string_error   = "";
    $warning_string = "";
	
	for ($i = 0; $i < POST('nconfs'); $i++)
	{
        if(POST("conf_$i") == "pass_length_max")
		{
            $pass_length_max = POST("value_$i");
            continue;
        }
		
		if(POST("conf_$i") == "pass_expire"){
            $pass_expire_max = POST("value_$i");
        }
		
		if(POST("conf_$i") == "pass_expire_min"){
            $pass_expire_min = POST("value_$i");
        }

		if(in_array(POST("conf_$i"), $numeric_values) && intval(POST("value_$i"))<0 )
		{
            $variable = "<strong>".$_SESSION['_main']['conf_'.$i]."</strong>";
            
            if(empty($warning_string)) {
                $warning_string .= _("Configuration successfully updated, but we found the following errors:");
            }
            
            $warning_string     .= "<BR />"._("Invalid $variable, it has to be greater than zero.");

            $flag_status         = 3;
            
            $_POST["value_$i"]   = 0;
        }
        
        if( POST("conf_$i") == "pass_length_min" )
		{
            if (POST("value_$i")<1) {
                $_POST["value_$i"] = 7;
            }
            $pass_length_min = POST("value_$i");
        }
		
        ossim_valid(POST("value_$i"), OSS_ALPHA, OSS_NULLABLE, OSS_SCORE, OSS_DOT, OSS_PUNC, "\{\}\|;\(\)\%", 'illegal:' . POST("conf_$i")); 
        
        if( POST("value_$i") != "" ) {
            if (!(ossim_error() || (valid_value(POST("conf_$i") , POST("value_$i"), $numeric_values, &$s_error))))    //
            {
                if ($flag_status==2){
                    $string_error .= "<br />";
				}
				
                $string_error .= $s_error;
                $flag_status=2;
            }
        }
	}
	if ( $flag_status != 2 )
	{
		for ($i = 0; $i < POST('nconfs'); $i++)
		{
			if ( isset($_POST["conf_$i"]) && isset($_POST["value_$i"]) )
			{
				if ( ($pass_fields[POST("conf_$i")] == 1 && Util::is_fake_pass(POST("value_$i"))) || POST("value_$i") == "skip_this_config_value" ){
					continue;
				}
				else
				{
					$before_value = $ossim_conf->get_conf(POST("conf_$i"),false); 
					$config->update(POST("conf_$i") , POST("value_$i"));
					
					if ( POST("value_$i") != $before_value ){ 
						Log_action::log(7, array("variable: ".POST("conf_$i")));
					}
				}
			}
		}
	}

    // check valid pass length max
    if(intval($pass_length_max) < intval($pass_length_min) || intval($pass_length_max) < 1 || intval($pass_length_max) > 255 ){
        $config->update("pass_length_max" , 255);
    }
    else{
        $config->update("pass_length_max" , intval($pass_length_max));
    }
    
	// check valid expire min - max
    if ($pass_expire_max * 60 * 24 < $pass_expire_min) {
    	$config->update("pass_expire_min" , 0);
    }

    /*  $infolog = array(
        $_SESSION['_user']
    );
    Log_action::log(7, $infolog);*/
	header("Location: " . $_SERVER['SCRIPT_NAME'] . "?adv=" . POST('adv') . "&word=" . POST('word') . "&section=" . POST('section') . "&status=" . $flag_status . "&error=" . urlencode($string_error) . "&warning=" . urlencode($warning_string));

    exit();
}

if (REQUEST("reset"))
{
    if ( !(GET('confirm')) ) 
	{
		?>
        <p align="center">
			<b><?php echo gettext("Are you sure ?") ?></b><br/>
			<a href="?reset=1&confirm=1"><?php echo gettext("Yes") ?></a>&nbsp;|&nbsp;
			<a href="main.php"><?php echo gettext("No") ?></a>
        </p>
		<?php
        exit();
    }
	
    require_once 'classes/Config.inc';
    $config = new Config();
    $config->reset();
    header("Location: " . $_SERVER['SCRIPT_NAME'] . "?adv=" . POST('adv') . "&word=" . POST('word') . "&section=" . POST('section'));
    exit;
}

$default_open = intval(GET('open'));
?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html>
<head>
	<title> <?php echo gettext("Advanced Configuration"); ?> </title>
	<meta http-equiv="Pragma" content="no-cache"/>
	<link rel="stylesheet" type="text/css" href="../style/style.css"/>
	<script src="../js/jquery.min.js" type="text/javascript" ></script>
	<script src="../js/accordian.js" type="text/javascript" ></script>
	<style type="text/css">
		
		#basic-accordian{
			padding:5px 5px 10px 5px;
			text-align:center;
			width:470px;
		}

		.accordion_headings {
			height:24px; 
			line-height:22px;
			cursor:pointer;
			padding-left:5px; 
			padding-right:5px; 
			margin-bottom:2px;
			font-size:12px; 
			color:#0E3C70; 
			font-weight:bold; 
			text-decoration:none;
		}

		.accordion_child {
			padding: 7px 5px 5px 5px;
		}		
		
		.semiopaque { opacity:0.9; MozOpacity:0.9; KhtmlOpacity:0.9; filter:alpha(opacity=90); background-color:#B5C3CF }
		
		.m_nobborder { border: none; background: none; }
		
		.ossim_success { padding: 15px 10px !important;}

		#basic-accordian td{ border-bottom: solid 1px #CCCCCC;}
	</style>
	

	<script type='text/javascript'>
		var IE = document.all ? true : false
		if (!IE) document.captureEvents(Event.MOUSEMOVE)
		document.onmousemove = getMouseXY;
		var tempX = 0;
		var tempY = 0;

		var difX = 15;
		var difY = 0; 

		function getMouseXY(e)
		{
			if (IE) { // grab the x-y pos.s if browser is IE
					tempX = event.clientX + document.body.scrollLeft + difX
					tempY = event.clientY + document.body.scrollTop + difY 
			} else {  // grab the x-y pos.s if browser is MOZ
					tempX = e.pageX + difX
					tempY = e.pageY + difY
			}  
			if (tempX < 0){tempX = 0}
			if (tempY < 0){tempY = 0}
			
			var dh = document.body.clientHeight+ window.scrollY;
			if (document.getElementById("numeroDiv").offsetHeight+tempY > dh)
				tempY = tempY - (document.getElementById("numeroDiv").offsetHeight + tempY - dh)
			document.getElementById("numeroDiv").style.left = tempX+"px";
			document.getElementById("numeroDiv").style.top = tempY+"px"; 
			return true
		}
	
		function ticketon(name,desc)
		{ 
			
			if (document.getElementById) {
				var txt1 = '<table border="0" cellpadding="8" cellspacing="0" class="semiopaque"><tr><td class="nobborder" style="line-height:18px;width:300px" nowrap="nowrap"><b>'+ name +'</b><br>'+ desc +'</td></tr></table>'
				document.getElementById("numeroDiv").innerHTML = txt1
				document.getElementById("numeroDiv").style.display = ''
				document.getElementById("numeroDiv").style.visibility = 'visible'
			}
		}

		function ticketoff()
		{
			if (document.getElementById) {
				document.getElementById("numeroDiv").style.visibility = 'hidden'
				document.getElementById("numeroDiv").style.display = 'none'
				document.getElementById("numeroDiv").innerHTML = ''
			}
		}
	
		// show/hide some options
		<?php
		if ($ossim_conf->get_conf("server_sem", FALSE) == "yes")
			echo "var valsem = 1;";
		else 
			echo "var valsem = 0;";

		if ($ossim_conf->get_conf("server_sim", FALSE) == "yes") 
			echo "var valsim = 1;";
		else 
			echo "var valsim = 0;";
		?>

		function enableall()
		{
			tsim("yes")
			tsem("yes")
        }
				
		function tsim(val)
		{
			if (val == "yes") valsim = 1;
			else valsim = 0;
			//document.getElementById('correlate_select').disabled = false;
			//document.getElementById('cross_correlate_select').disabled = false;
			//document.getElementById('store_select').disabled = false;
			//document.getElementById('qualify_select').disabled = false;
			$('#correlate_select').css('color','black');
			$('#cross_correlate_select').css('color','black');
			$('#store_select').css('color','black');
			$('#qualify_select').css('color','black');
			
			if (valsim==0)
			{
				//document.getElementById('correlate_select').disabled = true;
				//document.getElementById('cross_correlate_select').disabled = true;
				//document.getElementById('store_select').disabled = true;
				//document.getElementById('qualify_select').disabled = true;
				$('#correlate_select').css('color','gray');
				$('#cross_correlate_select').css('color','gray');
				$('#store_select').css('color','gray');
				$('#qualify_select').css('color','gray');
			}
			
			if (valsim==0 && valsem==0)
			{
				//document.getElementById('forward_alarm_select').disabled = true;
				//document.getElementById('forward_event_select').disabled = true;
				$('#forward_alarm_select').css('color','gray');
				$('#forward_event_select').css('color','gray');
			} 
			else
			{
				<?php if (Session::is_pro()) { ?>
				//document.getElementById('forward_alarm_select').disabled = false;
				//document.getElementById('forward_event_select').disabled = false;
				$('#forward_alarm_select').css('color','black');
				$('#forward_event_select').css('color','black');
				<?php } ?>
			}
		}
	
        function tsem(val)
		{
			if (val == "yes") 
				valsem = 1;
			else 
				valsem = 0;
			
			//document.getElementById('sign_select').disabled = false;
			$('#sign_select').css('color','black');
			
			if (valsem==0)
			{
				//document.getElementById('sign_select').disabled = true;
				$('#sign_select').css('color','gray');
			}
			if (valsim==0 && valsem==0)
			{
				//document.getElementById('forward_alarm_select').disabled = true;
				//document.getElementById('forward_event_select').disabled = true;
				$('#forward_alarm_select').css('color','gray');
				$('#forward_event_select').css('color','gray');
			} 
			else
			{
				//document.getElementById('forward_alarm_select').disabled = false;
				//document.getElementById('forward_event_select').disabled = false;
				$('#forward_alarm_select').css('color','black');
				$('#forward_event_select').css('color','black');
			}
		}

		function setvalue(id,val,checked)
		{
			var current = document.getElementById(id).value;
			current = current.replace(val,"");
			if (checked) current += val;
			document.getElementById(id).value = current;
		}
        
        function fword()
        {
            if($("#word").val().length>1) {
                $("#idf").submit();
            }
            else {
                alert('<?php echo  Util::js_entities(_("The search word must have at least two characters"))?>');
            }
        }

        function change_alarms_lifetime(val) {
			if (val == "yes") {
				document.getElementById('alarms_lifetime').value = 7;
				$('#alarms_lifetime').css('color','black');
			} else {
				document.getElementById('alarms_lifetime').value = 0;
				$('#alarms_lifetime').css('color','gray');
			}
        }

        function change_ldap_port(val) {
            if (val == "no" && document.getElementById('ldap_port').value == '639') {
                document.getElementById('ldap_port').value = '389';
            } else if (val == "yes" && document.getElementById('ldap_port').value == '389') {
                document.getElementById('ldap_port').value = '639';
            }
        }
        
        <?php
        if (session::is_pro())
		{
			?>
        
			function change_ldap_need_user(val) 
			{
				if (val == "no"){
					$('#user_entity').removeAttr('disabled');
					$('#user_menu').removeAttr('disabled');
				} 
				else 
				{
					$('#user_entity').attr('disabled','disabled');
					$('#user_menu').attr('disabled','disabled');
				}
			}
        
			<?php
        }
		else
		{
            //it is because the opensource version not have entities or menu template
            unset($CONFIG['Login']['conf']['login_create_not_existing_user_entity']);
            unset($CONFIG['Login']['conf']['login_create_not_existing_user_menu']);
        }
        ?>
        
        // Use this function to enable or disable some options from a select
        function enable_disable(val, classname) {
			if (val == "yes") {
				$('.'+classname).css('color','black');
				$('.'+classname).removeAttr('disabled');
			} else if (val == "no") {
				$('.'+classname).css('color','grey');
				$('.'+classname).attr('disabled','disabled');
			}
        }
	
        
        $(document).ready(function(){	
			<?php 
            
            if (GET('section') == "" && POST('section') == "" ) 
            { 
                ?>
                new Accordian('basic-accordian',5,'header_highlight');
                <?php 
            } 
            
            ?>
			// enable/disable by default
			$('input:hidden').each(function(){
				if ($(this).val()=='server_sim') {
					var idi = $(this).attr('name').substr(5);
					tsim($("select[name='value_"+idi+"']").val());
				}
				if ($(this).val()=='server_sem') {
					var idi = $(this).attr('name').substr(5);
					tsem($("select[name='value_"+idi+"']").val());
				}
			});
			
			$('.conf_items').each(function(index) {
				$(this).find("tr:last td").css('border', 'none');
			 });

			<?php	if (intval(GET('passpolicy'))==1)  { ?>
                $('#test10-header').click(); 
			<?php  }  ?>
			
			<?php	if ($default_open>0)  { ?>
                $('#test<?=$default_open?>-header').click(); 
			<?php  }  ?>
            
            $('#idf').bind('keypress', function(event) {
                if( event.keyCode==13)
                {
                    event.preventDefault();
                    var id_focus = event.target.id
                                                                                             
                    if ( id_focus == 'word' )
                    {
                        if ( $('#word').val() != '' )
                        {
                            fword();
                        }
                    }
                    else
                    {
                        $('#update').trigger('click');
                    }
                }
            });
            
            $('#search').bind('click', function() { fword(); });
              
            <?php
            if (session::is_pro()){
            ?>
            
            change_ldap_need_user('<?php echo ($ossim_conf->get_conf("login_ldap_require_a_valid_ossim_user", FALSE)) ?>');
            
            <?php
            }
            ?>
  
		});
        
	</script>

</head>

<body>

	<div id="numeroDiv" style="position:absolute; z-index:999; left:0px; top:0px; height:80px; visibility:hidden; display:none"></div>
	<?php
	$advanced = (POST('adv') == "1") ? true : ((GET('adv') == "1") ? true : false);
	$section = (POST('section') != "") ? POST('section') : GET('section');
	//$links = ($advanced) ? "<a href='main.php' style='color:#cccccc'>simple</a> | <b>advanced</b>" : "<b>simple</b> | <a href='main.php?adv=1' style='color:#cccccc'>advanced</a>";
	//$title = ($advanced) ? "Advanced" : "Main";
	if ($section == "") {
		include ("../hmenu.php");
	}

	$onsubmit = ( GET('adv') == '1' ) ? "onsubmit='enableall();'" : "";
	   	
	if ($flag_status == 1)
	{
        $txt   = $status_message;
        $ntype = "nf_success";
	}elseif($flag_status == 2)
	{
        $txt   = _("We found the following errors");
        $txt  .= "<BR/>".$status_message;
        $ntype = "nf_error";
	}
    elseif($flag_status == 3) {
        $txt   = $warning_string;
        $ntype = "nf_warning";
    }

    unset($_SESSION['_main']);
    
    if($flag_status == 1 || $flag_status == 2 || $flag_status == 3) {
        
        $config_nt = array(
                'content' => $txt,
                'options' => array (
                    'type'          => $ntype,
                    'cancel_button' => false
                ),
                'style'   => 'width: 80%; margin: 20px auto; text-align: left;'
            ); 
                            
        $nt = new Notification('nt_1', $config_nt);
        $nt->show();
    }
    
	?>
	
	<form method="POST" id="idf" style="margin:0px auto" <?php echo $onsubmit;?> action="<?php echo $_SERVER["SCRIPT_NAME"] ?>" />
  
	<br><br>
	<table align='center'>
	
	<tr>
		<td class="noborder">
			<div id="basic-accordian" align="center">
				<?php
				$count  = 0;
				$div    = 0;
				$found  = 0;
				$arr    = array();
												
				foreach($CONFIG as $key => $val) 
					if ($advanced || ($section == "" && !$advanced && $val["advanced"] == 0) || ($section != "" && preg_match("/$section/",$val['section'])))
					{
						$s = (POST('word') != "") ? POST('word') : ((GET('word') != "") ? GET('word') : "");
						
						if ($s != "")
						{
							foreach($val["conf"] as $conf => $type) 
								if ($advanced || ($section == "" && !$advanced && $type["advanced"] == 0) || ($section != "" && preg_match("/$section/",$type['section'])))
								{
									$pattern = preg_quote($s, "/");
                                    if (preg_match("/$pattern/i", $type["desc"]))
									{
										$found = 1;
										array_push($arr, $conf);
									}
								}
						}
					?>
			
					<div id="test<?php
						if ($div > 0) echo $div ?>-header" class="accordion_headings <?php
						if ($found == 1) echo "header_highlight" ?>">

						<table width="100%" cellspacing="0" class='m_nobborder'>
							<tr>
								<th  <?php
										if ($found == 1) echo "style='background-color: #F28020; color: #FFFFFF'" ?>>
										<?php echo $val["title"] ?>
								</th>
							</tr>
						</table>
					</div>
  
					<div id="test<?php
						if ($div > 0) echo $div ?>-content">
						<div class="accordion_child">
							<table class='conf_items' cellpadding='3' align="center">
							<?php
				            //print "<tr><th colspan=\"2\">" . $val["title"] . "</th></tr>";
				            print "<tr><td colspan='3'>" . $val["desc"] . "</td></tr>";
							
							if ($advanced && $val["title"]=="Policy")
							{
							?>
								<tr>
									<td colspan="3" align="center" class='nobborder'>
										<a target='topmenu' href='<?php echo "../top.php?hmenu=".md5("Intelligence")."&smenu=".md5("Policy")."&url=".urlencode("policy/reorderpolicies.php") ?>'>[ <?php echo _("Re-order Policies") ?>]<a/> 
									</td>
								</tr>
								<?php
							}
								
							foreach($val["conf"] as $conf => $type) 
							{
								if ($advanced || ($section == "" && !$advanced && $type["advanced"] == 0) || ($section != "" && preg_match("/$section/",$type['section'])))
								{
									//var_dump($type["type"]);
									$conf_value = $ossim_conf->get_conf($conf,false);
									$var        = ($type["desc"] != "") ? $type["desc"] : $conf;
									?>
								
								<tr <?php if (in_array($conf, $arr)) echo "bgcolor=#DFF2BF" ?>>
                                    <?php
                                        $_SESSION['_main']['conf_'.$count] = $var;
                                    ?>
									<input type="hidden" name="conf_<?php echo $count ?>" value="<?php echo $conf ?>" />
									
									<td <?php if ($type['style'] != "") echo "style='".$type['style']."'" ?> <?php if ($type['classname'] != "") echo "class='".$type['classname']."'" ?>><strong><?php echo (in_array($conf, $arr)) ? "<span style='color:#4F8A10'>".$var."</span>" : $var; ?></strong></td>
									
									<td class="left" style="white-space:nowrap">
										<?php
											$input = "";
											
											$disabled = ($type["disabled"] == 1 || $ossim_conf->is_in_file($conf)) ? "class='disabled' style='color:gray' disabled='disabled'" : "";
											$style    = ($type["style"] != "") ? "style='".$type["style"]."'" : "";
											
											/* select */
											if (is_array($type["type"]))
											{
												// Multiple checkbox
												if ($type['checkboxlist'])
												{
													$input .= "<input type='hidden' name='value_$count' id='".$type['id']."' value='$conf_value'/>";
													foreach($type["type"] as $option_value => $option_text)
													{
														$input.= "<input type='checkbox' onclick=\"setvalue('".$type['id']."',this.value,this.checked);\"";
														if (preg_match("/$option_value/",$conf_value)) 
															$input.= " checked='checked' ";
														
														$input.= "value='$option_value'/>$option_text<br/>";
													}
												// Select combo
												} 
												else
												{
													$select_change = ($type['onchange'] != "") ? "onchange=\"".$type['onchange']."\"" : "";
													$select_id = ($type['id'] != "") ? "id=\"".$type['id']."\"" : "";
													$input.= "<select name='value_$count' $select_change $select_id $disabled>";
													if ($type['value'] != "") { $conf_value = $type['value']; }
													
													if ($conf_value == "") 
														$input.= "<option value=''></option>";
													
													foreach($type["type"] as $option_value => $option_text)
													{
														$input.= "<option ";
														if ($conf_value == $option_value) 
															$input.= " selected='selected' ";
														
														$input.= "value='$option_value'>$option_text</option>";
													}
													
													$input.= "</select>";
												}
											}
											/* textarea */
											elseif ($type["type"]=="textarea")
											{
												$input.= "<textarea rows='2' cols='28' name=\"value_$count\" $disabled>$conf_value</textarea>";
											}
											/* link */
											elseif ($type["type"]=="link")
											{
												$input.= $type['value'];
											}
											/* Custom HTML value is ignored */
											elseif ($type["type"]=="html")
											{
												$input.= $type['value']."<input type='hidden' name='value_$count' value='skip_this_config_value'>";
											}
											/* input */
											else
											{
												$conf_value = ( $type["type"]=="password" ) ? Util::fake_pass($conf_value) : $conf_value;
												$input_id = ($type['id'] != "") ? "id=\"".$type['id']."\"" : "";
												$classname = ($type['classname'] != "") ? "class=\"".$type['classname']."\"" : "";
												$input.= "<input type='" . $type["type"] . "' size='30' name='value_$count' $style $input_id $classname value='$conf_value' $disabled/>";
											}
											
											echo $input;
											
										?>
										</td>
					
										<td align="left">
											<a href="javascript:;" onmouseover="ticketon('<?php echo str_replace("'", "\'", $var) ?>','<?php echo str_replace("\n"," ",str_replace("'", "\'", $type["help"])) ?>')"  onmouseout="ticketoff();">
												<img src="../pixmaps/help.png" width="16" border='0'/>
											</a>
										</td>

									</tr>
									
									<?php
									$count+= 1;
								}
							}
							?>
							</table>
				
							</div>
						</div>
						<?php
						$div++;
						$found = 0;
					}
					?>
				</div>
		  
			</td>
			
			<td valign='top' class="noborder">
				<?php 
                    submit(); 
                    echo _("Find word:");?><input type="text" style="margin-left:5px;" id="word" name="word" value="<?php echo $s ?>"/>
				<br/><br/>
				<input type='hidden' name="adv" value="<?php echo ($advanced) ? "1" : "" ?>"/>
				<input type='hidden' name="section" value="<?php echo $section ?>"/>
				<input type="button" name="search" id='search' class="button"  value="<?php echo _('Search')?>"/>
				<input type="hidden" name="nconfs" value="<?php echo $count ?>"/>
			</td>
		</tr>
	</table>
</form>
<a name="end"></a>
</body>
</html>
