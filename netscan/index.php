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
require_once ("classes/Session.inc");
require_once ("ossim_db.inc");
require_once ("ossim_conf.inc");
require_once ("classes/Net.inc");
require_once ("classes/Scan.inc");
require_once ("classes/Host.inc");
require_once ("classes/Sensor.inc");
require_once ("classes/Scan.inc");

Session::logcheck("MenuPolicy", "ToolsScan");

$db   = new ossim_db();
$conn = $db->connect();

$keytree = "assets";

$net_group_list = Net_group::get_list($conn);

$net_list = Net::get_list($conn);
$assets   = array();

foreach ($net_list as $_net) {
	$assets_aux[] = '{ txt:"NET:'.$_net->get_name().' ['.$_net->get_ips().']", id: "'.$_net->get_id().'#'.$_net->get_ips().'" }';
}

$host_list = Host::get_list($conn);
foreach ($host_list as $_host) {
    // get host IPs
    $hIPs = array();
    $hIPs = explode(",", trim($_host->get_ip())); 
    foreach($hIPs as $hIP) {
        $hIP = trim($hIP);
        $assets_aux[] = '{ txt:"HOST:'.$hIP . ' [' .$_host->get_hostname().']", id: "'.$_host->get_id().'#'.$hIP.'/32" }';
    }
}

$host_group_list = 	Host_group::get_list($conn);
foreach ($host_group_list as $_host_group)
{
    $hosts  = $_host_group->get_hosts($conn, $_host_group->get_id());

    $ids    = array();
    foreach ($hosts as $k => $v){
        $host_object = Host::get_object($conn, $v->get_host_id());
        $ids[] = $v->get_host_id()."#".$host_object->get_ip()."/32";
    }
    $assets_aux[] = '{ txt:"HOSTGROUP:'.$_host_group->get_name().'", id: "'.implode(",", $ids).'" }';
}

$sensor_list = Sensor::get_list($conn, "ORDER BY name");
foreach ($sensor_list as $_sensor) {
	$assets_aux[] = '{ txt:"SENSOR:'.$_sensor->get_name().' ['.$_sensor->get_ip().']", id: "'.$_host->get_id().'#'.$_sensor->get_ip().'/32" }';
}


$assets = implode(",\n", $assets_aux);

$db->close($conn);


$conf      = $GLOBALS["CONF"];
$nmap_path = $conf->get_conf("nmap_path");

$nmap_exists  = ( file_exists($nmap_path) ) ? 1 : 0;
$nmap_running = Scan::scanning_now();

$clearscan = ( !empty($_GET['clearscan']) && $_GET['clearscan'] == 1 ) ? 1 : 0;

if ( $clearscan == 1 )
{ 
	$scan = new Scan("");
	Scan::del_scan($scan->nmap_completed_scan);
}

?>

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html>
<head>
	<title> <?php echo gettext("OSSIM Framework"); ?> </title>
	<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1"/>
	<meta http-equiv="Pragma" content="no-cache"/>
	<script type="text/javascript" src="../js/combos.js"></script>
	<script type="text/javascript" src="../js/jquery.min.js"></script>
	<script type="text/javascript" src="../js/notification.js"></script>
	<script type="text/javascript" src="../js/messages.php"></script>
	<script type="text/javascript" src="../js/jquery-ui.min.js"></script>
	<script type="text/javascript" src="../js/jquery.cookie.js"></script>
	<script type="text/javascript" src="../js/jquery.dynatree.js"></script>
	<script type="text/javascript" src="../js/jquery.autocomplete.pack.js"></script>
	<script type="text/javascript" src="../js/jquery.tipTip.js"></script>
	<script type="text/javascript" src="../js/utils.js"></script>
	
	<link rel="stylesheet" type="text/css" href="../style/style.css"/>
	<link rel="stylesheet" type="text/css" href="../style/jquery-ui-1.7.custom.css"/>
	<link rel="stylesheet" type="text/css" href="../style/jquery.autocomplete.css">
	<link rel="stylesheet" type="text/css" href="../style/tree.css" />
	<link rel="stylesheet" type="text/css" href="../style/tipTip.css" />
	
	
	<script type='text/javascript'>
		
		var timer = null;
		
        function show_process_status() {
            $.ajax({
                type: "GET",
				data: 'clearscan=<?php echo GET('clearscan')?>',
                url: 'get_state.php',
                success: function(html){
					
					var width = $("#t_ad").css('width');
					$("#output").css('width', width);
										
					if( $("#process").contents().text() != "" )
					{
						$("#process_div").html("");
						$("#output").show();
						
						var offset = $("#output").offset();
						window.scrollTo(0, offset.top);
					}
					else
					{
						var data = html.split('###');
												
						var status  = data[0];
						var content = data[1];						
						
						if ( status == 'in_progress' )
						{
							if ( $("#process_div").html() != content && content != "" ) 
							{
								$("#process_div").html(content);
								$("#process_div").show();
								$("#output").show();
								
								var offset = $("#output").offset();
								window.scrollTo(0, offset.top);
							}
						}
						else if ( status == 'result' )
						{
							$("#output").hide();
							$("#process_div").html("");
							$("#scan_result").html(content);
							$("#scan_result").show();
							
							var offset = $("#scan_result").offset();
							window.scrollTo(0, offset.top);
							
							clearInterval(timer);							
						}
					}
				}
            });
        }
		
		function start_scan()
		{
			if( getcombotext("assets").length < 1 )
			{
				alert('<?php echo Util::js_entities(_("You must choose at least one asset"))?>');
				return false;
			}
			else
			{
                selectall("assets");
				$("#process").contents().find("#res_container").remove();
				$('#process').css('height', '200px');
				
				var data = $('#assets_form').serialize();
				$.ajax({
					type: "GET",
					url: 'do_scan.php',
					data: data + "&validate_all=true",
                    async: false,
					success: function(html){

						var status = parseInt(html);
											
						if ( status == 1 )
						{
							$("#error_messages").html('');
							$("#error_messages").css('display', 'none');
							
							$('#scan_button').removeClass();
							$('#scan_button').attr('disabled', 'disabled');
							$('#scan_button').addClass('buttonoff');
							$('#assets_form').submit();
						}
						else
						{
							var config_nt = {content: html, 
								options: {
									type: 'nf_error',
									cancel_button: false,
								},
								style: 'width: 95%; margin: auto; text-align:left;'
							};

							nt            = new Notification('nt_1', config_nt);
							notification  = nt.show();
							
							$('#error_messages').html(notification);
							$('#error_messages').show();
						}						
					}
				});			
			}
		}
		
		function remote_scan(){
			document.location.href='remote_scans.php';
		}
		
		function stop_nmap(asset, id) {
			
			$.ajax({
				type: "POST",
				url: "do_scan.php?only_stop=1&assets="+asset,
				beforeSend: function(xhr){
					$('#stop_'+id).attr('value', '<?php echo _("Stopping scan...")?>');
				},
				success: function(msg){
															
					$('#res_container').remove();
					$('#scan_button').removeAttr('disabled');
					$('#scan_button').removeClass();
					$('#scan_button').addClass('button');
					$('#assets_'+id).remove();
					$('#process_div').hide();
				}
			});
		}
		
		$(document).ready(function(){
            $("#assets_form").keypress(function(e) {
                if ( e.which == 13 ) {
                return false;
                }
			});
            
			show_process_status();
			
			timer = setInterval(show_process_status,5000);
            
            $("#atree").dynatree({
                initAjax: { url: "../tree.php?key=<?php echo $keytree ?>" },
                clickFolderMode: 2,
                onActivate: function(dtnode) {
                    if(dtnode.data.url!='' && typeof(dtnode.data.url)!='undefined') {
                        var Regexp = /.*_(\w+)/;
                        var match  = Regexp.exec(dtnode.data.key);
                        var id     = "";

                        id = match[1];

                        // Split for multiple IP/CIDR
						var keys = dtnode.data.val.split(",");

						for (var i = 0; i < keys.length; i++) {
							var item   = keys[i];
							var value  = "";
	                        var text   = "";
	                        
	                        if (item.match(/\d+\.\d+\.\d+\.\d+\/\d+/) !== null) { // net
	                            Regexp = /(\d+\.\d+\.\d+\.\d+\/\d+)/;
	                            match  = Regexp.exec(item);
	                            
	                            value = id + "#" + match[1];
	                            text  = match[1];
	                        }
	                        else if (item.match(/\d+\.\d+\.\d+\.\d+/) !== null) { // host
	                            Regexp = /(\d+\.\d+\.\d+\.\d+)/;
	                            match  = Regexp.exec(item);
	                            
	                            value = id + "#" + match[1];
	                            text  = match[1] + "/32";
	                        }
	                     
	                        if(value !="" && text !="") {
	                            addto ("assets", text, value);
	                        }
						}
                    }
                },
                onDeactivate: function(dtnode) {},
                onLazyRead: function(dtnode){
                    dtnode.appendAjax({
                        url: "../tree.php",
                        data: {key: dtnode.data.key, page: dtnode.data.page}
                    });
                }
			});
            
			$("#searchBox").click(function() {
                $("#searchBox").removeClass('greyfont');
                $("#searchBox").val('');
                });
            
			$("#searchBox").blur(function() {
                $("#searchBox").addClass('greyfont');
                $("#searchBox").val('<?php echo _("Type here to search assets")?>');
            });
            
			$('#searchBox').keydown(function(event) {
                if (event.which == 13) {
                    addto ("assets", $("#searchBox").val() , $("#searchBox").val() );
                    $("#searchBox").val("");
                }
            });

            // Autocomplete assets
            var assets = [ <?php echo preg_replace("/,$/","",$assets); ?> ];
            
            $("#searchBox").autocomplete(assets, {
                minChars: 0,
                width: 300,
                max: 100,
                matchContains: true,
                autoFill: true,
                formatItem: function(row, i, max) {
                    return row.txt;
                }
            }).result(function(event, item) {
                var data = item.id.split("#");
                
                addto ("assets", data[1] , item.id);
                $("#searchBox").val("");
            });
			
						
			if ( $(".hostname_info").length >= 1 ) {
				$(".hostname_info").tipTip({maxWidth: "auto"});
			}
		});

        function change_scan_type(val) {
            if (val == "custom") {
				$('.div_custom').show();
            } else {
            	$('.div_custom').hide();
            }
        }
	</script>
  
	<style type='text/css'>
		
		#t_ad {width: 570px;}
		
		th { padding: 3px 0px;}
		
		.container {
			margin:auto; 
			padding: 20px 30px;
		}
		
		#process_div {
			width: 570px;
			background: transparent;
			margin: 20px auto;
		}
						
		#process { 
			height: 100%;
			width: 100%;
			background: transparent;
            margin: 0px auto;
            border: 0px;
		}
		
		#output{
			display:none; 
			padding: 10px 0px 20px 0px;
		}
		
		#scan_result{
			display:none; 
		}
		
		.loading_nmap{
			padding-top: 8px;
		}
		
				
		small { color: grey; }
		
		.div_small { padding: 5px 0px 0px 1px;}
		
		.cidr_info {
			cursor:pointer; 
			text-decoration: none;
			outline: none;
		}
		
		.cidr_info div {
			text-decoration: none;
			outline: none;
		}
		
		#tree {margin: 15px auto 5px auto; text-align: left;}
		
		#error_messages {
			display: none;
			width: 750px;
			margin: 10px auto;
			
		}
		
		.ossim_error { width: auto;}
		
		.error_item { 
			padding-left: 25px; 
			text-align: left;
		}
        
        .greyfont{
            color: #666666;
        }
        #assets {
            width:310px;
            height:180px;
        }
		
		.hostname_info img{
			cursor: pointer;
		}
	</style>
  
</head>

<body>

<?php
$typeMenu='horizontal';
include ("../hmenu.php");

if ( !$nmap_exists ) 
{
    require_once ("ossim_error.inc");
    $error = new OssimError();
    $error->display("NMAP_PATH");
}
?>
<!-- Asset form -->

<div id='error_messages'></div>

<form name="assets_form" id="assets_form" method="get" action="do_scan.php" target="process">
	<table align="center" id='t_ad'>
		<tr>
			<th colspan="2"><?php echo gettext("Please, select the assets you want to scan:") ?></th>
		</tr>
		<tr>
			<td class='container nobborder'>
                <table class="transparent">
                    <tr>
                        <td colspan="2" class="nobborder" style="text-align:left;">
                            <input style="width:220px;margin-left:3px;" class="greyfont" type="text" id="searchBox" value="<?php echo _("Type here to search assets"); ?>" />
                        </td>
                    </tr>
                    <tr>
                        <td class="nobborder" style="vertical-align:top" class="nobborder">
                            <table class="transparent">
                                <tr>
                                    <td class="nobborder">
                                    <select id="assets" name="assets[]" multiple="multiple"></select>
                                    </td>
                                </tr>
                                <tr>
                                    <td class="nobborder" style="text-align:right">
                                        <input type="button" value=" [X] " onclick="deletefrom('assets')" class="lbutton"/>
                                        <input type="button" style="margin-right:0px;"value="Delete all" onclick="selectall('assets');deletefrom('assets')" class="lbutton"/>
                                    </td>
                                </tr>
                                <tr>
                                	<td class="nobborder">
                                		<table class="transparent">
                                			<tr><td class="nobborder" nowrap="nowrap"><input type="radio" name="sensor" value="auto" checked> <?php echo "<b>"._("Automatic")."</b> "._("sensor") ?> <small><?php echo _("Launch scan from the first available sensor") ?></small></td></tr>
	                                		<tr><td class="nobborder" nowrap="nowrap"><input type="radio" name="sensor" value="null" checked> <?php echo "<b>"._("Local")."</b> "._("scan") ?> <small><?php echo _(" Launch scan from the framework machine") ?></small></td></tr>
                                		</table>
                                	</td>
                                </tr>
                                <tr>
									<td style="text-align: left; border:none; padding-top:3px; padding-left:8px">
										<a href="" onclick="$('#sensor_div').toggle(); if($('#sensor_div').is(':visible')){ $('#sensors_arrow').attr('src','../pixmaps/arrow_green_down.gif'); } else{ $('#sensors_arrow').attr('src','../pixmaps/arrow_green.gif'); } return false;"><img id="sensors_arrow" border="0" align="absmiddle" src="../pixmaps/arrow_green.gif"/><?php echo _("Select a")." <b>"._("specific sensor")."</b>" ?></a>
									</td>
								</tr>
								<tr id="sensor_div" style="display:none">
									<td class="nobborder">
										<table class="transparent">
											<?php
											foreach ($sensor_list as $sensor) {
											?>
											<tr><td class="nobborder"><input type="radio" name="sensor" value="<?php echo $sensor->get_id() ?>"> <?php echo $sensor->get_name()." [".$sensor->get_ip()."]" ?></td></tr>
											<?php } ?>
										</table>
									</td>
								</tr>
                            </table>
                        </td>
                        <td class="nobborder" width="300px;" style="vertical-align: top;">
                            <div id="atree" style="text-align:left;width:100%;margin-left:15px;"></div>
                        </td>
                    </tr>
                </table>
			</td>
        </tr>
		<tr>
			<th colspan="2"><?php echo _("Assets Discovery Options")?></th>
		</tr>

		<!-- full scan -->
		<tr>
			<td colspan="2" class='container'>
				<?php echo _("Scan type")?>:&nbsp;
				<select name="full_scan" onchange="change_scan_type(this.value)">
					<option value="ping"><?php echo _("Ping")?></option>
					<option value="normal" selected='selected'><?php echo _("Normal")?></option>
					<option value="fast"><?php echo _("Fast Scan")?></option>
					<option value="full"><?php echo _("Full Scan")?></option>
					<option value="custom"><?php echo _("Custom")?></option>
				</select>
				<div class='div_custom' style="display:none;padding-top:10px;padding-bottom:10px">
					<?php echo _("Specify Ports") ?>: <input type="text" name="custom_ports" value="">
				</div>
				<div class='div_small'>
					<small>
						<strong><?php echo _("Full mode")?></strong> <?php echo _("will be much slower but will include OS, services, service versions and MAC address into the inventory")?><br/>
						<strong><?php echo _("Fast mode")?></strong> <?php echo _("will scan fewer ports than the default scan")?>
					</small>
				</div>
			</td>
		</tr>
		<!-- end full scan -->

		<!-- timing template (T0-5) -->
		<tr>
			<td colspan="2" class='container'>
				<?php echo _("Timing template")?>:&nbsp;
				<select name="timing_template">
					<option value="-T0"><?php echo _("Paranoid")?></option>
					<option value="-T1"><?php echo _("Sneaky")?></option>
					<option value="-T2"><?php echo _("Polite")?></option>
					<option selected='selected' value="-T3"><?php echo _("Normal")?></option>
					<option value="-T4"><?php echo _("Aggressive")?></option>
					<option value="-T5"><?php echo _("Insane")?></option>
				</select>
				
				<div class='div_small'>
					<small>
						<strong><?php echo _("Paranoid")?></strong> <?php echo _("and")?> <strong><?php echo _("Sneaky")?></strong> <?php echo _("modes are for IDS evasion")?><br/>
						<strong><?php echo _("Polite")?></strong> <?php echo _("mode slows down the scan to use less bandwidth and target machine resources")?><br/>
						<strong><?php echo _("Aggressive")?></strong> <?php echo _("and")?> <strong><?php echo _("Insane")?></strong> <?php echo _("modes speed up the scan (fast and reliable networks)")?><br/>
					</small>
				</div>
			</td>
		</tr>
		<!-- end timing template -->
		<!-- timing template (T0-5) -->
		<tr>
			<td colspan="2" class='container'>
				<input type="checkbox" name="autodetect" value="1" checked='checked'/> <?php echo _("Autodetect services and Operating System") ?>
				<br /><input type="checkbox" name="rdns" value="1" checked='checked'/> <?php echo _("Enable reverse DNS Resolution") ?>
				<br /><input type="checkbox" name="vcad" value="1" checked='checked'/> <?php echo _("Run Quick Vulnerability Scan") ?>
			</td>
		</tr>

		<!-- do scan -->
		<tr>
			<td colspan="2" class="nobborder center" style='padding: 10px;'>
				<?php
					if ( !$nmap_exists || $nmap_running )
					{
						$disabled    = " disabled='disabled'";
						$input_class = "buttonoff";
					}
					else
					{
						$disabled    = "";
						$input_class = "button";
					}
				?>
			
				<input type="button" id="scan_button" class="<?php echo $input_class?>" onclick="start_scan();" value="<?php echo _("Start Scan") ?>"<?php echo $disabled?>/>
			
				<?php 
				if (Session::am_i_admin()) 
				{ 
					?>&nbsp;&nbsp;
					<input type="button" class="button" value="<?php echo _("Manage Remote Scans") ?>" onclick="remote_scan()"/>
					<?php 
				} 
				?>
			
			</td>
		</tr>
		
	</table>
	
	<br />
	
	<table align="center" style='width: 580px; display:none' id="output">
        <tr>
            <td class="nobborder">
                <div id='process_div' style="text-align:center"></div>
            </td>
        </tr>
        <tr>
            <td class="nobborder">
				<iframe frameborder="0" name="process" id="process"> </iframe>
            </td>
        </tr>
        <br/><br/>
    </table>
	
	<div id='scan_result'></div>
	
    <br/>
</form>


<!-- end of Asset form -->
</body>
</html>