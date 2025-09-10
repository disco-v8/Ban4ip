<?php
// ------------------------------------------------------------
// 
// BAN for iptables/ip6tables
// 
// T.Kabu/MyDNS.JP           http://www.MyDNS.JP/
// Future Versatile Group    http://www.fvg-on.net/
// 
// ------------------------------------------------------------
?>
<?php
// ----------------------------------------------------------------------
// Sub Routine
// ----------------------------------------------------------------------
require(__DIR__."/ban4ipd_ban.php");
?>
<?php
// ----------------------------------------------------------------------
// Sub Routine
// ----------------------------------------------------------------------
require(__DIR__."/ban4ipd_unban.php");
?>
<?php
// ----------------------------------------------------------------------
// Sub Routine
// ----------------------------------------------------------------------
require(__DIR__."/ban4ipd_exec.php");
?>
<?php
// ----------------------------------------------------------------------
// Sub Routine
// ----------------------------------------------------------------------
function get_ipv4_range($IPV4_ADDRESS)
{
    // 対象アドレスを分割
    @list($TARGET_ADDRESS, $TARGET_MASK) = explode("/", $IPV4_ADDRESS);
    
    // IPv4アドレスを整数に変換
    $TARGET_ADDRESS_LONG = ip2long($TARGET_ADDRESS);
    
    // プレフィックスに基づいてネットワークアドレスを計算
    $TARGET_ADDRESS_MASK = -1 << (32 - $TARGET_MASK);
    $TARGET_NETWORK_LONG = $TARGET_ADDRESS_LONG & $TARGET_ADDRESS_MASK;
    
    // ブロードキャストアドレスを計算
    $TARGET_BROADCAST_LONG = $TARGET_NETWORK_LONG | (~$TARGET_ADDRESS_MASK & 0xFFFFFFFF);
    
    // アドレスを戻す
    $TARGET_NETWORK_ADDRESS = long2ip($TARGET_NETWORK_LONG);
    $TARGET_BROADCAST_ADDRESS = long2ip($TARGET_BROADCAST_LONG);
    
    return [
        $TARGET_NETWORK_ADDRESS,
        $TARGET_BROADCAST_ADDRESS,
    ];
}
?>
<?php
// ----------------------------------------------------------------------
// Sub Routine
// ----------------------------------------------------------------------
function get_ipv6_range($IPV6_ADDRESS)
{
    // 対象アドレスを分割
    @list($TARGET_ADDRESS, $TARGET_MASK) = explode("/", $IPV6_ADDRESS);
    
    // IPv6アドレスをバイナリ形式に変換
    $TARGET_ADDRESS_BINARY = inet_pton($TARGET_ADDRESS);
    $TARGET_ADDRESS_BINARY = str_pad($TARGET_ADDRESS_BINARY, 16, "\0"); // 128ビットにパディング
    
    // プレフィックスに基づいてネットワークアドレスを計算
    $TARGET_NETWORK_BINARY = substr($TARGET_ADDRESS_BINARY, 0, $TARGET_MASK / 8) . str_repeat("\0", 16 - ($TARGET_MASK / 8));

    // ブロードキャストアドレス（最大アドレス）を計算
    $TARGET_BROADCAST_BINARY = substr($TARGET_ADDRESS_BINARY, 0, $TARGET_MASK / 8) . str_repeat("\xff", 16 - ($TARGET_MASK / 8));

    // バイナリ形式から文字列形式に戻す
    $TARGET_NETWORK_ADDRESS = inet_ntop($TARGET_NETWORK_BINARY);
    $TARGET_BROADCAST_ADDRESS = inet_ntop($TARGET_BROADCAST_BINARY);

    return [
        $TARGET_NETWORK_ADDRESS,
        $TARGET_BROADCAST_ADDRESS,
    ];
}
?>
<?php
// ----------------------------------------------------------------------
// Sub Routine
// ----------------------------------------------------------------------
function get_networkaddr($IP_ADDR, $IP_MASK)
{
    // 対象IPアドレスをバイナリ形式に変換
    $ADDR['pack'] = inet_pton($IP_ADDR);
    // バイナリ形式に変換できなかったら
    if ($ADDR['pack'] == FALSE)
    {
        // 戻る
        return FALSE;
    }
    
    // 対象IPアドレスがIPv6なら(IPv6だったら文字列そのものが返ってくる)
    if (filter_var($IP_ADDR, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== FALSE)
    {
        // IPv6なのに、マスク値が0～128でなかったら
        if ($IP_MASK < 0 || $IP_MASK > 128)
        {
            // 戻る
            return FALSE;
        }
        @list($TARGET_NETWORK_ADDRESS, $TARGET_BROADCAST_ADDRESS) = get_ipv6_range($IP_ADDR.'/'.$IP_MASK);
    }
    // 対象IPアドレスがIPv4なら(IPv4だったら文字列そのものが返ってくる)
    else if (filter_var($IP_ADDR, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== FALSE)
    {
        // IPv4なのに、マスク値が0～32でなかったら
        if ($IP_MASK < 0 || $IP_MASK > 32)
        {
            // 戻る
            return FALSE;
        }
        @list($TARGET_NETWORK_ADDRESS, $TARGET_BROADCAST_ADDRESS) = get_ipv4_range($IP_ADDR.'/'.$IP_MASK);
    }
    else
    {
        // 戻る
        return FALSE;
    }
    
    // ネットワークアドレスと連結して返す
    return $TARGET_NETWORK_ADDRESS.'/'.$IP_MASK;
}
?>
<?php
// ----------------------------------------------------------------------
// Sub Routine
// ----------------------------------------------------------------------
function check_safeaddr($TARGET_CONF)
{
    // ホワイトリスト設定がないなら
    if (!isset($TARGET_CONF['safe_address']) || !is_array($TARGET_CONF['safe_address']))
    {
        // 戻る(対象IPアドレスはホワイトリストに含まれていない)
        return FALSE;
    }
    
    // まずはホワイトリストのネットワークアドレスとブロードキャストアドレスを取得
    // ホワイトアドレスがネットワーク型ではないなら、両方とも同じアドレスにする
    
    // 続いて対象IPアドレスについても同様に取得 
    // 最終的にすべてが合致するかでホワイトかどうか(TRUE/FALSE)を判断
    
    // 対象IPアドレスを/で分割して配列に設定
    @list($TARGET_ADDRESS, $TARGET_MASK) = explode("/", $TARGET_CONF['target_address']);
    
    // 対象IPアドレスがホワイトリストの中にあるかどうか確認
    foreach ($TARGET_CONF['safe_address'] as $SAFE_ADDRESS)
    {
        // ホワイトIPアドレスを/で分割して配列に設定
        @list($SAFE_ADDRESS, $SAFE_MASK) = explode("/", $SAFE_ADDRESS);
        
        // ホワイトIPアドレスがIPv6なら(IP6だったら文字列そのものが返ってくる)
        if (filter_var($SAFE_ADDRESS, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== FALSE)
        {
            // ホワイトIPアドレスがネットワークアドレス指定なら
            if (isset($SAFE_MASK) && ($SAFE_MASK >= 0 && $SAFE_MASK <= 128))
            {
                // ホワイトIPアドレスのネットワークアドレスとブロードキャストアドレスを取得
                @list($SAFE_NETWORK_ADDRESS, $SAFE_BROADCAST_ADDRESS) = get_ipv6_range($SAFE_ADDRESS.'/'.$SAFE_MASK);
                
                // 対象IPアドレスもIPv6アドレスなら(IPv6だったら文字列そのものが返ってくる)
                if (filter_var($TARGET_ADDRESS, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== FALSE)
                {
                    // 対象IPアドレスがネットワークアドレス指定なら
                    if (isset($TARGET_MASK) && ($TARGET_MASK >= 0 && $TARGET_MASK <= 128))
                    {
                        // 対象IPアドレスをホワイトリストのネットマスクでネットワークアドレスとブロードキャストアドレスを取得
                        @list($TARGET_NETWORK_ADDRESS, $TARGET_BROADCAST_ADDRESS) = get_ipv6_range($TARGET_ADDRESS.'/'.$SAFE_MASK);
                    }
                    // 対象IPアドレスが単独アドレスなら
                    else
                    {
                        // 対象IPアドレスをホワイトリストのネットマスクでネットワークアドレスとブロードキャストアドレスを取得
                        @list($TARGET_NETWORK_ADDRESS, $TARGET_BROADCAST_ADDRESS) = get_ipv6_range($TARGET_ADDRESS.'/'.$SAFE_MASK);
                    }
                    // 対象IPアドレスとホワイトIPアドレスが等しいなら
                    if ($TARGET_NETWORK_ADDRESS === $SAFE_NETWORK_ADDRESS && $TARGET_BROADCAST_ADDRESS === $SAFE_BROADCAST_ADDRESS)
                    {
                        // 戻る(対象IPアドレスはホワイトリストに含まれている)
                        return TRUE;
                    }
                }
            }
            // ホワイトIPアドレスが単独アドレスなら
            else
            {
                // ホワイトIPアドレスのネットワークアドレスとブロードキャストアドレスを同一として設定
                $SAFE_NETWORK_ADDRESS = $SAFE_ADDRESS;
                $SAFE_BROADCAST_ADDRESS = $SAFE_ADDRESS;
            }
            // 対象IPアドレスもIPv6アドレスなら(IPv6だったら文字列そのものが返ってくる)
            if (filter_var($TARGET_ADDRESS, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== FALSE)
            {
                // 対象IPアドレスがネットワークアドレス指定なら
                if (isset($TARGET_MASK) && ($TARGET_MASK >= 0 && $TARGET_MASK <= 128))
                {
                }
                // 対象IPアドレスも単独アドレスなら
                else
                {
                    // 対象IPアドレスとホワイトIPアドレスが等しいなら
                    if ($TARGET_ADDRESS === $SAFE_ADDRESS)
                    {
                        // 戻る(対象IPアドレスはホワイトリストに含まれている)
                        return TRUE;
                    }
                }
            }
        }
         
        // ホワイトIPアドレスがIPv4なら(IP4だったら文字列そのものが返ってくる)
        if (filter_var($SAFE_ADDRESS, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== FALSE)
        {
            // ホワイトIPアドレスがネットワークアドレス指定なら
            if (isset($SAFE_MASK) && ($SAFE_MASK >= 0 && $SAFE_MASK <= 32))
            {
                // ホワイトIPアドレスのネットワークアドレスとブロードキャストアドレスを取得
                @list($SAFE_NETWORK_ADDRESS, $SAFE_BROADCAST_ADDRESS) = get_ipv4_range($SAFE_ADDRESS.'/'.$SAFE_MASK);
                
                // 対象IPアドレスもIPv4アドレスなら(IPv4だったら文字列そのものが返ってくる)
                if (filter_var($TARGET_ADDRESS, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== FALSE)
                {
                    // 対象IPアドレスがネットワークアドレス指定なら
                    if (isset($TARGET_MASK) && ($TARGET_MASK >= 0 && $TARGET_MASK <= 32))
                    {
                        // 対象IPアドレスをホワイトリストのネットマスクでネットワークアドレスとブロードキャストアドレスを取得
                        @list($TARGET_NETWORK_ADDRESS, $TARGET_BROADCAST_ADDRESS) = get_ipv4_range($TARGET_ADDRESS.'/'.$SAFE_MASK);
                    }
                    // 対象IPアドレスが単独アドレスなら
                    else
                    {
                        // 対象IPアドレスをホワイトリストのネットマスクでネットワークアドレスとブロードキャストアドレスを取得
                        @list($TARGET_NETWORK_ADDRESS, $TARGET_BROADCAST_ADDRESS) = get_ipv4_range($TARGET_ADDRESS.'/'.$SAFE_MASK);
                    }
                    
                    // 対象IPアドレスとホワイトIPアドレスが等しいなら
                    if ($TARGET_NETWORK_ADDRESS === $SAFE_NETWORK_ADDRESS && $TARGET_BROADCAST_ADDRESS === $SAFE_BROADCAST_ADDRESS)
                    {
                        // 戻る(対象IPアドレスはホワイトリストに含まれている)
                        return TRUE;
                    }
                }
            }
            // ホワイトIPアドレスが単独アドレスなら
            else
            {
                // ホワイトIPアドレスのネットワークアドレスとブロードキャストアドレスを同一として設定
                $SAFE_NETWORK_ADDRESS = $SAFE_ADDRESS;
                $SAFE_BROADCAST_ADDRESS = $SAFE_ADDRESS;
            }
            // 対象IPアドレスもIPv4アドレスなら(IPv4だったら文字列そのものが返ってくる)
            if (filter_var($TARGET_ADDRESS, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== FALSE)
            {
                // 対象IPアドレスがネットワークアドレス指定なら
                if (isset($TARGET_MASK) && ($TARGET_MASK >= 0 && $TARGET_MASK <= 32))
                {
                }
                // 対象IPアドレスも単独アドレスなら
                else
                {
                    // 対象IPアドレスとホワイトIPアドレスが等しいなら
                    if ($TARGET_ADDRESS === $SAFE_ADDRESS)
                    {
                        // 戻る(対象IPアドレスはホワイトリストに含まれている)
                        return TRUE;
                    }
                }
            }
        }
    }
    // 戻る(上記以外は対象IPアドレスはホワイトリストに含まれてない)
    return FALSE;
}
?>
<?php
// ----------------------------------------------------------------------
// Sub Routine
// ----------------------------------------------------------------------
function check_safekeyword($TARGET_CONF)
{
    // ホワイトリスト設定がないなら
    if (!isset($TARGET_CONF['safe_keyword']) || !is_array($TARGET_CONF['safe_keyword']))
    {
        // 戻る(対象キーワードはホワイトリストに含まれていない)
        return FALSE;
    }
    
    // 対象キーワードがホワイトリストの中にあるかどうか確認
    foreach ($TARGET_CONF['safe_keyword'] as $SAFE_ADDRESS)
    {
        // 対象キーワードを設定
        $TARGET_ADDRESS = $TARGET_CONF['target_keyword'];
        
        // 対象キーワードとホワイトキーワードが等しいなら
        if ($TARGET_ADDRESS === $SAFE_ADDRESS)
        {
            // 戻る(対象キーワードはホワイトリストに含まれている)
            return TRUE;
        }
    }
    // 戻る(対象キーワードはホワイトリストに含まれていない)
    return FALSE;
}
?>
<?php
// ----------------------------------------------------------------------
// Sub Routine
// ----------------------------------------------------------------------
function issbanlistget($TARGET_CONF)
{
    // 情報共有サーバーのBANデータベースからBAN情報を取ってくるための変数を設定
    $ISS_INFO = array(
        "iss_get_time" => $TARGET_CONF['iss_get_time'],
        "iss_get_limit" => $TARGET_CONF['iss_get_limit'],
        "iss_get_myreport" => $TARGET_CONF['iss_get_myreport']
        );
    
    // JSON形式に変換
    $ISS_JSON = json_encode($ISS_INFO);
     
    // ストリームコンテキストのオプションを作成
    $ISS_OPTION = array(
        // HTTPコンテキストオプションをセット
        'http' => array(
        'method'=> 'POST',
        'header'=> 'Content-type: application/json; charset=UTF-8', //JSON形式を指定
        'content' => $ISS_JSON
        )
    );
    
    // ストリームコンテキストの作成
    $ISS_CONTEXT = stream_context_create($ISS_OPTION);
    
    // POST送信
    $ISS_RESULT = @file_get_contents('https://'.$TARGET_CONF['iss_username'].':'.$TARGET_CONF['iss_password'].'@'.$TARGET_CONF['iss_server'].'/banget.html', false, $ISS_CONTEXT);
    
    // POST出来なかったら
    if ($ISS_RESULT === false)
    {
        $TARGET_CONF['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4ip[".getmypid()."]: ERROR [iss-list] "."Cannot get Ban List!? "."\n";
        // ログに出力する
        log_write($TARGET_CONF);
    }
    // BAN情報一覧の取得ができたら
    else
    {
        // BAN情報が必要最低限長(75文字)もなかったら
        if (strlen($ISS_RESULT) < 72)
        {
            $TARGET_CONF['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4ip[".getmypid()."]: INFO [iss-list] "."None new Ban List"."\n";
            // ログに出力する
            log_write($TARGET_CONF);
        }
        // JSON エンコードされたBAN情報一覧をPHPの変数に変換、出来なかったら
        else if (($ISS_BAN_LIST = json_decode($ISS_RESULT, TRUE)) == NULL)
        {
            $TARGET_CONF['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4ip[".getmypid()."]: ERROR [iss-list] "."Cannot decode Ban List!? ".$ISS_RESULT."\n";
            // ログに出力する
            log_write($TARGET_CONF);
        }
        // BAN情報一覧をPHPの変数に変換出来たら
        else
        {
            // 変数化したBAN情報一覧を一つずつBANする
            foreach ($ISS_BAN_LIST as $ISS_BAN_INFO)
            {
                // BANする(UNIXタイム)
                $TARGET_CONF['target_address'] = $ISS_BAN_INFO['address'];
                $TARGET_CONF['target_service'] = $ISS_BAN_INFO['service'];
                $TARGET_CONF['target_protcol'] = $ISS_BAN_INFO['protcol'];
                $TARGET_CONF['target_port'] = $ISS_BAN_INFO['port'];
                $TARGET_CONF['target_rule'] = $ISS_BAN_INFO['rule'];
////                $TARGET_CONF['logtime'] = local_time();
                $TARGET_CONF['logtime'] = time();
                
                // 対象IPアドレスがホワイトリストの中にあるかどうか確認
                if (check_safeaddr($TARGET_CONF) == TRUE)
                {
                    // ホワイトリストである旨のメッセージを設定
                    $TARGET_CONF['log_msg'] = date("Y-m-d H:i:s", $TARGET_CONF['logtime'])." ban4nft[".getmypid()."]: INFO [".$TARGET_CONF['target_service']."] Safe ".$TARGET_CONF['target_address']."\n";
                    // ログに出力する
                    log_write($TARGET_CONF);
                    // 次の対象文字列検査へ
                    continue;
                }
                
                // 対象IPアドレスがIPv6なら(IPv6だったら文字列そのものが返ってくる)
                if (filter_var($TARGET_CONF['target_address'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== FALSE)
                {
                    // IPv6マスク値が設定されていて、/128以外(0～127)なら
                    if (isset($TARGET_CONF['ipv6_netmask']) && ($TARGET_CONF['ipv6_netmask'] >= 0 && $TARGET_CONF['ipv6_netmask'] < 128))
                    {
                        // 対象IPアドレスにマスク値を追加したアドレス表記を、対象ネットワークアドレスとする
                        $TARGET_ADDRESS = get_networkaddr($TARGET_CONF['target_address'], $TARGET_CONF['ipv6_netmask']);
                        // 対象ネットワークアドレスが正常に取得できたなら
                        if ($TARGET_ADDRESS != FALSE)
                        {
                            // 対象ネットワークアドレスを対象IPアドレスとして設定
                            $TARGET_CONF['target_address'] = $TARGET_ADDRESS;
                        }
                    }
                }
                // 対象IPアドレスがIPv4なら(IPv4だったら文字列そのものが返ってくる)
                else if (filter_var($TARGET_CONF['target_address'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== FALSE)
                {
                    // IPv4マスク値が設定されていて、/32以外(0～31)なら
                    if (isset($TARGET_CONF['ipv4_netmask']) && ($TARGET_CONF['ipv4_netmask'] >= 0 && $TARGET_CONF['ipv4_netmask'] < 32))
                    {
                        // 対象IPアドレスにマスク値を追加したアドレス表記を、対象ネットワークアドレスとする
                        $TARGET_ADDRESS = get_networkaddr($TARGET_CONF['target_address'], $TARGET_CONF['ipv4_netmask']);
                        // 対象ネットワークアドレスが正常に取得できたなら
                        if ($TARGET_ADDRESS != FALSE)
                        {
                            // 対象ネットワークアドレスを対象IPアドレスとして設定
                            $TARGET_CONF['target_address'] = $TARGET_ADDRESS;
                        }
                    }
                }
                
                $TARGET_CONF = ban4ip_ban($TARGET_CONF);
                // ログに出力する
                log_write($TARGET_CONF);
            }
        }
    }
}
?>
<?php
// ----------------------------------------------------------------------
// Sub Routine
// ----------------------------------------------------------------------
function ban4ip_mail_send()
{
    // メール送信のパラメータを設定(それぞれのプロセスのTARGET_CONFがなかったり、宛先がなかったらFALSEで戻る。それ以外は空でも送信処理をする)
    $MAIL_ARG = func_get_args();
    // それぞれのプロセスのTARGET_CONFが設定されていなかったり、配列でなかったら
    if (!isset($MAIL_ARG[0]) || !is_array($MAIL_ARG[0]))
    {
        // FALSEで戻る
        return FALSE;
    }
    // パラメータがあるなら
    else
    {
        // TARGET_CONFを設定
        $TARGET_CONF = $MAIL_ARG[0];
    }
    
    // 宛先に相当するパラメータが設定されていないなら
    if (!isset($MAIL_ARG[1]))
    {
        // FALSEで戻る
        return FALSE;
    }
    // パラメータがあるなら
    else
    {
        // 宛先を設定
        $MAIL_TO = $MAIL_ARG[1];
    }
    
    // タイトルに相当するパラメータが設定されていないなら
    if (!isset($MAIL_ARG[2]))
    {
        // NULLを設定
        $MAIL_TITLE = NULL;
    }
    // パラメータがあるなら
    else
    {
        // タイトルを設定
        $MAIL_TITLE = $MAIL_ARG[2];
    }
    
    // 本文に相当するパラメータが設定されていないなら
    if (!isset($MAIL_ARG[3]))
    {
        // NULLを設定
        $MAIL_STR = NULL;
    }
    // パラメータがあるなら
    else
    {
        // 本文を設定
        $MAIL_STR = $MAIL_ARG[3];
    }
    
    // ヘッダーオプションに相当するパラメータが設定されていないなら
    if (!isset($MAIL_ARG[4]))
    {
        // NULLを設定
        $MAIL_HEADER = NULL;
    }
    // パラメータがあるなら
    else
    {
        // ヘッダーオプションを設定
        $MAIL_HEADER = $MAIL_ARG[4];
    }
    
    // メールオプションに相当するパラメータが設定されていないなら
    if (!isset($MAIL_ARG[5]))
    {
        // NULLを設定
        $MAIL_PARAM = NULL;
    }
    // パラメータがあるなら
    else
    {
        // メールオプションを設定
        $MAIL_PARAM = $MAIL_ARG[5];
    }
    
    // メール送信レートテーブルから、対象メッセージの現在時刻 - 対象時間より昔のデータを削除
    $SQL_STR = "DELETE FROM mailrate_tbl WHERE registdate < (".(time() - $TARGET_CONF['mailratetime']).");";
    $TARGET_CONF = ban4ip_db_exec($TARGET_CONF, 'mailrate_db', $SQL_STR);

    // メール送信レートテーブルに対象メッセージを登録
    $SQL_STR = "INSERT INTO mailrate_tbl VALUES ('".$MAIL_TO."','".$MAIL_TITLE."',".time().");";
    $TARGET_CONF = ban4ip_db_exec($TARGET_CONF, 'mailrate_db', $SQL_STR);
    // 登録できた件数を取得
    $RESULT = $TARGET_CONF['exec_result'];

    // もし新しく登録できたら
    if ($RESULT != 0)
    {
        // メール送信
        $RESULT = mb_send_mail(
                $MAIL_TO,
                $MAIL_TITLE,
                $MAIL_STR.$RESULT,
                $MAIL_HEADER,
                $MAIL_PARAM);
    }
    else
    {
        // メールは送信しない
    }
    // 戻る
    return $RESULT;
}
?>
<?php
// ----------------------------------------------------------------------
// Sub Routine
// ----------------------------------------------------------------------
function ban4ip_end($signo)
{
    global $BAN4IPD_CONF;
    
    // フォークした子プロセスがあるなら
    if (isset($BAN4IPD_CONF['proclist']) && is_array($BAN4IPD_CONF['proclist']))
    {
        // フォークした子プロセスをkillする
        foreach ($BAN4IPD_CONF['proclist'] as $PID)
        {
            // 子プロセスをkillする
            posix_kill($PID, SIGTERM);
            // 子プロセスの終了を待つ
            pcntl_waitpid($PID, $STATUS, WUNTRACED);
        }
    }
    unset($BAN4IPD_CONF['proclist']);
    
    // シグナル別に処理
    switch ($signo)
    {
        // SIGINTなら
        case SIGINT:
        // SIGTERMなら
        case SIGTERM:
            // ソケットファイルがあれば
            if (is_executable($BAN4IPD_CONF['socket_file']))
            {
                // UNIXソケットを閉じる
                socket_close($BAN4IPD_CONF['socket']);
                // ソケットファイルを削除する
                unlink($BAN4IPD_CONF['socket_file']);
            }
            
            // iptablesからban4ipチェインを削除する
            system($BAN4IPD_CONF['iptables'].' -D INPUT -j ban4ip');
            system($BAN4IPD_CONF['iptables'].' -F ban4ip');
            system($BAN4IPD_CONF['iptables'].' -X ban4ip');
            // ip6tablesからban4ipチェインを削除する
            system($BAN4IPD_CONF['ip6tables'].' -D INPUT -j ban4ip');
            system($BAN4IPD_CONF['ip6tables'].' -F ban4ip');
            system($BAN4IPD_CONF['ip6tables'].' -X ban4ip');
            
            // PIDファイルがあれば
            if (is_file($BAN4IPD_CONF['pid_file']))
            {
                // PIDファイルを削除する
                unlink($BAN4IPD_CONF['pid_file']);
            }
            
            $BAN4IPD_CONF['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4ip[".getmypid()."]: END"."\n";
            // ログに出力する
            log_write($BAN4IPD_CONF);
            // ログファイルポインタが開かれているなら
            if (isset($BAN4IPD_CONF['log_p']))
            {
                // ログファイルを閉じる
                fclose($BAN4IPD_CONF['log_p']);
            }
            // 終わり
            exit;
            break;
        // SIGHUPなら
        case SIGHUP:
            // ソケットファイルがあれば
            if (is_executable($BAN4IPD_CONF['socket_file']))
            {
                // UNIXソケットを閉じる
                socket_close($BAN4IPD_CONF['socket']);
                // ソケットファイルを削除する
                unlink($BAN4IPD_CONF['socket_file']);
            }
            
            // 再読み込み要求(=1)を設定
            $BAN4IPD_CONF['reload'] = 1;
            $BAN4IPD_CONF['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4ip[".getmypid()."]: RELOAD"."\n";
            // ログに出力する
            log_write($BAN4IPD_CONF);
            // ログファイルポインタが開かれているなら
            if (isset($BAN4IPD_CONF['log_p']))
            {
                // ログファイルを閉じる
                fclose($BAN4IPD_CONF['log_p']);
            }
            break;
    }
}
?>
<?php
// ----------------------------------------------------------------------
// Check Other process
// ----------------------------------------------------------------------
// PIDファイルがあるなら
if (is_file($BAN4IPD_CONF['pid_file']))
{
    // エラーメッセージに、別のプロセスがある旨を設定
    $ERR_MSG = 'Found other process : '.$BAN4IPD_CONF['pid_file'].'!?';
    // メッセージを表示
    print "\n".'ban4ipd ... '.$ERR_MSG."\n\n";
    // 終わり
    exit -1;
}
// ないなら
else
{
    // ログファイルの指定があるなら
    if (isset($BAN4IPD_CONF['log_file']))
    {
        // ファイルをtouch(無ければ新規作成)
        touch($BAN4IPD_CONF['log_file']);
        // ファイルのパーミッションを700に設定
        chmod($BAN4IPD_CONF['log_file'], 0600);
    }
    // PIDファイルを新規に開く
    $PID_FILE = fopen($BAN4IPD_CONF['pid_file'], "a");
    // PIDファイルにプロセスIDを出力(改行しない)
    fputs($PID_FILE, getmypid());
    // PIDファイルを閉じる
    fclose($PID_FILE);
}
?>
<?php
// ----------------------------------------------------------------------
// Check iptanles/ip6tables
// ----------------------------------------------------------------------
// iptables
if (!is_executable($BAN4IPD_CONF['iptables']))
{
    fprintf(STDERR, "Cannot execute iptables!?\n");
    exit -1;
}

// ip6tables
if (!is_executable($BAN4IPD_CONF['ip6tables']))
{
    fprintf(STDERR, "Cannot execute ip6tables!?\n");
    exit -1;
}

// -----------------------------
// iptablesからban4ip関連チェインを削除する
// -----------------------------
// INPUTチェインの設定を取得する
$PROC_P = popen($BAN4IPD_CONF['iptables']." -L INPUT -n", "r");
$TARGET_PATTERN = '/^ban4ip[\s]{1,}all /';
// INPUTチェインにban4ipチェインがあるなら
if (psearch($PROC_P, $TARGET_PATTERN) == TRUE)
{
    // INPUTチェインからban4ipチェインを削除
    system($BAN4IPD_CONF['iptables'].' -D INPUT -j ban4ip > /dev/null');
}
pclose($PROC_P);

// ban4ipチェインの設定を取得する
$PROC_P = popen($BAN4IPD_CONF['iptables']." -L -n", "r");
$TARGET_PATTERN = '/^Chain[\s]{1,}ban4ip /';
// ban4ipチェインがあるなら
if (psearch($PROC_P, $TARGET_PATTERN) == TRUE)
{
    // INPUTチェインからban4ipチェインを削除
    system($BAN4IPD_CONF['iptables'].' -F ban4ip > /dev/null');
    system($BAN4IPD_CONF['iptables'].' -X ban4ip > /dev/null');
}
pclose($PROC_P);

// -----------------------------
// ip6tablesからban4ip関連チェインを削除する
// -----------------------------
// INPUTチェインの設定を取得する
$PROC_P = popen($BAN4IPD_CONF['ip6tables']." -L INPUT -n", "r");
$TARGET_PATTERN = '/^ban4ip[\s]{1,}all /';
// INPUTチェインにban4ipチェインがあるなら
if (psearch($PROC_P, $TARGET_PATTERN) == TRUE)
{
    // INPUTチェインからban4ipチェインを削除
    system($BAN4IPD_CONF['ip6tables'].' -D INPUT -j ban4ip > /dev/null');
}
pclose($PROC_P);

// ban4ipチェインの設定を取得する
$PROC_P = popen($BAN4IPD_CONF['ip6tables']." -L -n", "r");
$TARGET_PATTERN = '/^Chain[\s]{1,}ban4ip /';
// ban4ipチェインがあるなら
if (psearch($PROC_P, $TARGET_PATTERN) == TRUE)
{
    // INPUTチェインからban4ipチェインを削除
    system($BAN4IPD_CONF['ip6tables'].' -F ban4ip > /dev/null');
    system($BAN4IPD_CONF['ip6tables'].' -X ban4ip > /dev/null');
}
pclose($PROC_P);

// iptablesにban4ipチェインを新設する
system($BAN4IPD_CONF['iptables'].' -N ban4ip');
system($BAN4IPD_CONF['iptables'].' -A ban4ip -j RETURN');
// ip6tablesにban4ipチェインを新設する
system($BAN4IPD_CONF['ip6tables'].' -N ban4ip');
system($BAN4IPD_CONF['ip6tables'].' -A ban4ip -j RETURN');

// iptablesのINPUTチェインにban4ipチェインを追加する(最初に)
system($BAN4IPD_CONF['iptables'].' -I INPUT -j ban4ip');
// ip6tablesのINPUTチェインにban4ipチェインを追加する(最初に)
system($BAN4IPD_CONF['ip6tables'].' -I INPUT -j ban4ip');
?>
<?php
// ----------------------------------------------------------------------
// Main (ここで監視設定(.conf)毎にプロセスを再度フォークする)
// ----------------------------------------------------------------------
do // SIGHUPに対応したループ構造にしている
{
    // 親プロセス用のデータベースの初期化(接続や必要に応じてテーブル生成)を行う
    // 2024.09.13 PostgreSQL/MySQLにも対応するために、データベースの初期化をBan4IPとは異なり、_init.php内からこちらに移動
    // 2024.10.09 ログへの書き出しを考慮してここに移動
    // 2025.09.05 いつの間にかDBの初期化を親プロセスのみでするようになっていて処理構造がおかしくなっていたのでdbinitを見直し
    $BAN4IPD_CONF = ban4ip_dbinit($BAN4IPD_CONF);
    
    // 再読み込み要求を初期化
    $BAN4IPD_CONF['reload'] = 0;
    
    // 情報共有フラグがON(=1)なら
    if (isset($BAN4IPD_CONF['iss_flag']) && $BAN4IPD_CONF['iss_flag'] == 1)
    {
        // 情報共有(ISS)関連の初期化処理
        // 2025.09.05 いつの間にかDBの初期化を親プロセスのみでするようになっていて処理構造がおかしくなっていたのでdbinitから分離
        ban4ip_issinit($BAN4IPD_CONF);
        
        // 初回だけは、過去の自分の報告も取得＆反映させる
        $ORG_INFO['iss_get_myreport'] = $BAN4IPD_CONF['iss_get_myreport'];
        $BAN4IPD_CONF['iss_get_myreport'] = 1;
        
        // 情報共有サーバーのBANデータベースからBAN情報を取ってくる
        issbanlistget($BAN4IPD_CONF);
        
        // 情報共有サーバーからBAN情報を取得した最終日時を設定
        $BAN4IPD_CONF['iss_last_time'] = time();
        //自分のBAN報告の取得設定を元の設定に戻す
        $BAN4IPD_CONF['iss_get_myreport'] = $ORG_INFO['iss_get_myreport'];
    }
    
    // サブ設定ディレクトリの設定があるなら
    if (isset($BAN4IPD_CONF['conf_dir']) && is_dir($BAN4IPD_CONF['conf_dir']))
    {
        // サブ設定ディレクトリを開く
        $CONF_DIR = opendir($BAN4IPD_CONF['conf_dir']);
        // サブ設定ディレクトリからファイルの一覧を取得
        while (($CONF_FILE = readdir($CONF_DIR)) !== false)
        {
            $BAN4IPD_CONF['conf_file'] = $BAN4IPD_CONF['conf_dir'].'/'.$CONF_FILE;
            // サブ設定ファイルなら
            if (is_file($BAN4IPD_CONF['conf_file']) && preg_match('/.conf$/', $BAN4IPD_CONF['conf_file']))
            {
                // プロセスをフォーク
                $PID = pcntl_fork();
                
                // フォークできなかったら
                if ($PID == -1)
                {
                    // エラーメッセージに、プロセスをフォークできない旨を設定
                    $ERR_MSG = 'Cannot fork process'.'!?';
                    // メッセージを表示
                    print "\n".'ban4ipd ... '.$ERR_MSG."\n\n";
                    // 終わり
                    exit -1;
                }
                // フォークできたら
                else if ($PID != 0)
                {
                    // 親プロセスの場合
                    $BAN4IPD_CONF['proclist'][] = $PID;
                }
                // 子プロセスなら
                else // if ($PID == 0)
                {
                    // 子プロセス用のサブルーチンファイルを読み込み
                    require(__DIR__.'/ban4ipd_sub.php');
                    // サブ設定ファイルを読み込んで変数展開する
                    $TARGET_CONF = array_merge($BAN4IPD_CONF, parse_ini_file($BAN4IPD_CONF['conf_file'], FALSE, INI_SCANNER_NORMAL));
                    // 子プロセス用のデータベースの初期化(接続や必要に応じてテーブル生成)を行う…実際には接続のみし直す
                    // 2025.09.05 いつの間にかDBの初期化を親プロセスのみでするようになっていて処理構造がおかしくなっていたのでdbinitを見直し
                    $TARGET_CONF = ban4ip_dbinit($TARGET_CONF);
                    // 実際の処理を開始
                    ban4ip_start($TARGET_CONF);
                    // ここで終わり(子プロセスなので)
                    exit;
                }
            }
        }
        closedir($CONF_DIR);
        
        // シグナルハンドラを設定します(親プロセスだけ)
        declare(ticks = 1);
        pcntl_signal(SIGINT,  "ban4ip_end");
        pcntl_signal(SIGTERM, "ban4ip_end");
        pcntl_signal(SIGHUP,  "ban4ip_end");
        
        // 親プロセスとしてUNIXソケットを開く
        $BAN4IPD_CONF['socket'] = socket_create(AF_UNIX, SOCK_DGRAM, 0);
        // UNIXソケットが開けなかったら
        if ($BAN4IPD_CONF['socket'] == FALSE )
        {
            // エラーメッセージに、UNIXソケットを開けない旨を設定
            $ERR_MSG = 'Cannot create socket'.'!?';
            // メッセージを表示
            print "\n".'ban4ipd ... '.$ERR_MSG."\n\n";
            // 終わり
            ban4ip_end(SIGTERM);
        }
        // UNIXソケットとファイルがBINDできなかったら
        if (socket_bind($BAN4IPD_CONF['socket'], $BAN4IPD_CONF['socket_file']) == FALSE)
        {
            // エラーメッセージに、UNIXソケットとファイルがBINDできない旨を設定
            $ERR_MSG = 'Cannot bind socket'.'!?';
            // メッセージを表示
            print "\n".'ban4ipd ... '.$ERR_MSG."\n\n";
            // 終わり
            ban4ip_end(SIGTERM);
        }
        // UNIXソケットをノンブロッキングモードに変更できなかったら
        if (socket_set_nonblock($BAN4IPD_CONF['socket']) == FALSE)
        {
            // エラーメッセージに、UNIXソケットをノンブロッキングモードに変更できない旨を設定
            $ERR_MSG = 'Cannot set non block socket'.'!?';
            // メッセージを表示
            print "\n".'ban4ipd ... '.$ERR_MSG."\n\n";
            // 終わり
            ban4ip_end(SIGTERM);
        }
        // UNIXソケットを配列に設定(読み込みできるかどうかだけ調べられればいいのでREAD_ARRAYに設定)
        $SOCK_READ_ARRAY = array($BAN4IPD_CONF['socket']);
        $SOCK_WRITE_ARRAY  = NULL;
        $SOCK_EXCEPT_ARRAY = NULL;
        
        // 親プロセスの開始完了を出力
        $BAN4IPD_CONF['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4ip[".getmypid()."]: START under ".$BAN4IPD_CONF['system_pid0']."\n";
        // ログに出力する
        log_write($BAN4IPD_CONF);
        
        // 再読み込み要求(=1)が来るまで無限ループ(親プロセスがSIGHUPを受けると1)
        while($BAN4IPD_CONF['reload'] == 0)
        {
            // 終わってしまった子プロセスのステータスを取得
            pcntl_wait($STATUS, WNOHANG);
            
            // UNIXソケットに変化が発生しているか(読み込みができるようになっているか)を取得、$BAN4IPD_CONF['unbantime']だけ待つ
            // (socket_selectによって変数が上書きされるので常に設定)
            $READ_ARRAY = $SOCK_READ_ARRAY;
            $WRITE_ARRAY = $SOCK_WRITE_ARRAY;
            $EXCEPT_ARRAY = $SOCK_EXCEPT_ARRAY;
            $SOCK_RESULT = @socket_select($READ_ARRAY, $WRITE_ARRAY, $EXCEPT_ARRAY, $BAN4IPD_CONF['unbantime']);
            // UNIXソケットの変化が取得できないなら
            if ($SOCK_RESULT === FALSE)
            {
                // 再読み込み要求(reload=1)ではないなら
                if ($BAN4IPD_CONF['reload'] != 1)
                {
                    $BAN4IPD_CONF['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4ip[".getmypid()."]: ERROR "." Cannot socket_select!? (".socket_strerror(socket_last_error()).")"."\n";
                    // ログに出力する
                    log_write($BAN4IPD_CONF);
                }
            }
            // UNIXソケットに変化がないなら
            else if ($SOCK_RESULT == 0)
            {
            }
            // 変化があるなら
            else if ($SOCK_RESULT > 0)
            {
                // ソケットからデータを受信して、ログメッセージに設定
                $SOCK_RESULT = socket_recvfrom($BAN4IPD_CONF['socket'], $BAN4IPD_CONF['log_msg'], 255, 0, $SOCK_FROM);
                // データの受信ができたなら
                if ($SOCK_RESULT != FALSE)
                {
                    // ログに出力する
                    log_write($BAN4IPD_CONF);
                }
                // できなかったら
                else
                {
                    $BAN4IPD_CONF['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4ip[".getmypid()."]: ERROR "." Cannot socket_recvfrom!? (".socket_strerror(socket_last_error()).")"."\n";
                    // ログに出力する
                    log_write($BAN4IPD_CONF);
                }
            }
            
            // 2025.09.09 T.Kabu 結局ここを含めて、exec()とquery()をラッピングすることにした
            // 2025.09.09 T.Kabu PDO経由でMySQLやPostgreSQLと接続していると、何らかの理由で勝手に切断されていることがあり、この後のtry/catchで「General error: 2006 MySQL server has gone away」エラーとなることがある
            // 2021.09.07 T.Kabu どうもSQLite3が、DELETEの時にだけ何かのタイミングでデータベースがロックしているという判断でエラーとなる。実際にはDELETE出来ているので再試行も発生しないので、try/catchでスルーするようにした
            $SQL_STR = "DELETE FROM count_tbl WHERE registdate < ".$BAN4IPD_CONF['maxfindtime'].";";
            $BAN4IPD_CONF = ban4ip_db_exec($BAN4IPD_CONF, 'count_db', $SQL_STR);

            // BANデータベースでBAN解除対象IPアドレスを取得(UNIXタイム)
            $SQL_STR = "SELECT * FROM ban_tbl WHERE unbandate < ".time().";";
            $RESULT = $BAN4IPD_CONF['ban_db']->query($SQL_STR);
            // BAN解除対象IPアドレスの取得ができなかったら
            if ($RESULT === FALSE)
            {
                $BAN4IPD_CONF['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4ip[".getmypid()."]: ERROR "." Cannot query!? (".socket_strerror(socket_last_error()).")"."\n";
                // ログに出力する
                log_write($BAN4IPD_CONF);
            }
            // BAN解除対象IPアドレスの取得ができたら
            else
            {
                // 該当データがあったらUNBANする
                while ($DB_DATA = $RESULT->fetch(PDO::FETCH_ASSOC))
                {
                    // UNBANする
                    $BAN4IPD_CONF['target_address'] = $DB_DATA['address'];
                    $BAN4IPD_CONF['target_service'] = $DB_DATA['service'];
                    $BAN4IPD_CONF['target_protcol'] = $DB_DATA['protcol'];
                    $BAN4IPD_CONF['target_port'] = $DB_DATA['port'];
                    $BAN4IPD_CONF['target_rule'] = $DB_DATA['rule'];
                    $BAN4IPD_CONF = ban4ip_unban($BAN4IPD_CONF);
                    // ログに出力する
                    log_write($BAN4IPD_CONF);
                }
                if (isset($TARGET_CONF['pdo_dsn_ban']) && preg_match('/^sqlite/', $TARGET_CONF['pdo_dsn_ban']))
                {
                    // WAL内のデータをDBに書き出し(こうしないとban4ipc listで確認したり、別プロセスでsqlite3ですぐに確認できない…が、負荷的にはWALにしている意味がないよなぁ…一応banの場合は発行時に、unbanはここですべてが終わった時に書き出し処理をする。count_dbはしない)
                    $SQL_STR = "PRAGMA wal_checkpoint;";
                    $BAN4IPD_CONF = ban4ip_db_exec($BAN4IPD_CONF, 'ban_db', $SQL_STR);
                }
            }
            // 情報共有フラグがON(=1)なら
            if (isset($BAN4IPD_CONF['iss_flag']) && $BAN4IPD_CONF['iss_flag'] == 1)
            {
                // 情報共有サーバーからBAN情報を取得した最終日時からnnn秒経過したら
                if (($BAN4IPD_CONF['iss_get_time'] = (time() - $BAN4IPD_CONF['iss_last_time'])) > 180)
                {
                    $BAN4IPD_CONF['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4ip[".getmypid()."]: INFO [iss-list] Request ISS Ban List "."\n";
                    // ログに出力する
                    log_write($BAN4IPD_CONF);
                    // 情報共有サーバーからBAN情報を取得した最終日時を設定
                    $BAN4IPD_CONF['iss_last_time'] = time();
                    // 情報共有サーバーのBANデータベースからBAN情報を取ってくる
                    issbanlistget($BAN4IPD_CONF);
                }
            }
        }
        
        // シグナルハンドラをデフォルトに戻します(親プロセスだけ)
        pcntl_signal(SIGHUP,  SIG_DFL);
        pcntl_signal(SIGTERM, SIG_DFL);
        pcntl_signal(SIGINT,  SIG_DFL);
        
        unset($BAN4IPD_CONF['proclist']);
    }
} while(1);
?>
