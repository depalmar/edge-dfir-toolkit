/*
   Mandiant's own hunting rules for the TINYSHELL code base, published with its UNC3886
   Junos report (March 2025). Reproduced as Mandiant printed them; only whitespace and the
   comments are this toolkit's. Hunting rules: they match TINYSHELL generally, not only the
   UNC3886 variants.

   Reference: https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-targets-juniper-routers
*/

rule M_Hunting_PacketEncryptionLayer_1
{
    meta:
        author = "Mandiant"
    strings:
        $pel_1 = "pel_client_init"
        $pel_2 = "pel_server_init"
        $pel_3 = "pel_setup_context"
        $pel_4 = "pel_send_msg"
        $pel_5 = "pel_recv_msg"
        $pel_6 = "pel_send_all"
        $pel_7 = "pel_recv_all"
        $pel_8 = "pel_errno"
        $pel_9 = "pel_context"
        $pel_10 = "pel_ctx"
        $pel_11 = "send_ctx"
        $pel_12 = "recv_ctx"
    condition:
        4 of ($pel_*)
}

rule M_Hunting_TINYSHELL_5
{
    meta:
        author = "Mandiant"
    strings:
        $tsh_1 = "tsh_get_file"
        $tsh_2 = "tsh_put_file"
        $tsh_3 = "tsh_runshell"
        $tshd_1 = "tshd_get_file"
        $tshd_2 = "tshd_put_file"
        $tshd_3 = "tshd_runshell"
    condition:
        all of ($tshd_*) or all of ($tsh_*)
}
