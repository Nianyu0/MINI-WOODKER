<?php
function  get_input_data()
{
    $data   =  file_get_contents("php://input");
    return  json_decode($data,  true);
}
   
function  respond($state,  $message,  $login_data = null)
{
    header('Content-Type: application/json');
    echo    json_encode(["state" => $state,  "message"  =>  $message,  "login_data"  =>  $login_data]);
}
                                      
function  member_register()
{
    $input  =  get_input_data();

    $user_name  =                     trim($input["user_Name"]);
    $pass_word  =  password_hash(trim($input["pass_Word"]),    PASSWORD_DEFAULT);
    $e_mail     =                     trim($input["e_Mail"]);
    $Phone     =                     trim($input["user_Phone"]);
    $Address     =                     trim($input["user_Address"]);

    if (isset($input["user_Name"],  $input["pass_Word"],  $input["e_Mail"],  $input["user_Phone"],  $input["user_Address"])) {

        if ($user_name  &&  $pass_word  &&  $e_mail  &&  $Phone  &&  $Address) {
            require_once("miniwoodker_conn_member.php");

            $stmt  =  $conn->prepare("INSERT INTO  `member`( `Username`, `Password`, `Email`, `Phone`, `Address`)   VALUES (  ?  ,  ?  ,  ?  ,  ?  ,  ?  )");
            $stmt->bind_param("sssss",      $user_name,  $pass_word,  $e_mail,  $Phone,  $Address);

            if ($stmt->execute()) {
                respond(true,  "註冊成功");
            } else {
                respond(false,  "註冊成功");
            }

            $stmt->close();
            $conn->close();
        } else {
            respond(false,  "輸入資料為「空值」");
        }
    } else {
        respond(false,  "欄位錯誤");
    }
}

function  member_login()
{
    $input  =  get_input_data();

    $user_name  =  trim($input["user_Name"]);
    $pass_word  =  trim($input["pass_Word"]);

    if (isset($input["user_Name"],  $input["pass_Word"])) {

        if ($user_name  &&  $pass_word) {
            require_once("miniwoodker_conn_member.php");

            $stmt  =  $conn->prepare("   SELECT    *    FROM `member` WHERE  `Username` =  ?   ");
            $stmt->bind_param("s",    $user_name);
            $stmt->execute();

            $result  =   $stmt->get_result();
            $row     =   $result->fetch_assoc();

            if ($result->num_rows === 1) {
                if (password_verify($pass_word,   $row["Password"])) {
                    $update_uid  =  substr(hash('sha256', time()),  10,  4)   .   substr(bin2hex(random_bytes(8)),  10,  4);
                    $update_stmt  =  $conn->prepare("   UPDATE   `member`   SET   `UID`=?    WHERE  `Username` =  ?   ");
                    $update_stmt->bind_param("ss",   $update_uid,    $user_name);
                    $update_stmt->execute();

                    if ($update_stmt->execute()) {
                        $user_stmt  =  $conn->prepare("   SELECT    *    FROM `member` WHERE  `Username` =  ?   ");
                        $user_stmt->bind_param("s",    $user_name);
                        $user_stmt->execute();
                        $user_result  =   $user_stmt->get_result();
                        $user_row     =   $user_result->fetch_assoc();
                                                                                              
                        unset($user_row["Password"]);                               
                        respond(true,  "登入成功,更新UID",  $user_row);
                    } else {
                        respond(false,  "登入失敗,無法建立UID");
                    }
                } else {
                    respond(false,  "密碼錯誤");
                }
            } else {
                respond(false,  "帳號錯誤");
            }

            $stmt->close();
            $conn->close();
        } else {
            respond(false,  "輸入資料為「空值」");
        }
    } else {
        respond(false,  "欄位錯誤");
    }
}

function  member_checkUID()
{
    $input  =  get_input_data();

    $user_uid  =  trim($input["UID"]);

    if (isset($input["UID"])) {
        if ($user_uid) {
            require_once("miniwoodker_conn_member.php");

            $stmt  =  $conn->prepare("   SELECT    *    FROM `member` WHERE  `UID` =  ?   ");
            $stmt->bind_param("s",    $user_uid);
            $stmt->execute();

            $result  =   $stmt->get_result();
            $row     =   $result->fetch_assoc();

            $num     =   $result->num_rows;

            if ($num === 1) {
                unset($row["Password"]);

                respond(true,  "驗證UID成功",  $row);
            } else {
                respond(false,  "驗證UID失敗");
            }

            $stmt->close();
            $conn->close();
        } else {
            respond(false,  "UID為「空值」");
        }
    } else {
        respond(false,  "UID欄位錯誤");
    }
}

function  member_checkNAME()
{
    $input  =  get_input_data();
    $user_name  =  trim($input["user_Name"]);

    if (isset($input["user_Name"])) {

        if ($user_name) {
            require_once("miniwoodker_conn_member.php");

            $stmt  =  $conn->prepare("   SELECT    *    FROM `member` WHERE  `Username` =  ?   ");

            $stmt->bind_param("s",    $user_name);
            $stmt->execute();

            $result  =   $stmt->get_result();
            $row     =   $result->fetch_assoc();
            $num     =   $result->num_rows;

            if ($num === 1) {
                unset($row["Password"]);

                respond(false,  "帳號已存在，不可使用");
            } else {
                respond(true,  "帳號可以註冊使用");
            }

            $stmt->close();
            $conn->close();
        } else {
            respond(false,  "username 帳號 為「空值」");
        }
    } else {
        respond(false,  "username 帳號 欄位錯誤");
    }
}

function  get_SQL_member()
{
    require_once("miniwoodker_conn_member.php");

    $stmt  =  $conn->prepare("   SELECT    *    FROM   `member`      ");
    $stmt->execute();
    $result  =   $stmt->get_result();
    $num     =   $result->num_rows;

    if ($num  >  0) {

        while ($row  =   $result->fetch_assoc()) {
            $SQL_data[]  =  $row;
        }

        respond(true,  "取出「資料庫」之會員資料",  $SQL_data);
    } else {
        respond(false,  "「資料庫」沒有會員資料");
    }

    $stmt->close();
    $conn->close();
}

function  get_SQL_getownerdata()
{
    $input  =  get_input_data();
    $UID    =  trim($input["UID"]);

    require_once("miniwoodker_conn_member.php");

    $stmt  =  $conn->prepare("   SELECT    *    FROM   `member`  Where  `UID`=?  ");
    $stmt->bind_param("s",    $UID);
    $stmt->execute();

    $result  =   $stmt->get_result();

    $num     =   $result->num_rows;

    if ($num  >  0) {

        while ($row  =   $result->fetch_assoc()) {
            $SQL_data[]  =  $row;
        }

        respond(true,  "取出「資料庫」之會員資料",  $SQL_data);
    } else {
        respond(false,  "「資料庫」沒有會員資料");
    }

    $stmt->close();
    $conn->close();
}


function  update_member()
{
    $input  =  get_input_data();

    $user_name    = isset($input["Username"]) ? trim($input["Username"]) : null;
    $user_email   = isset($input["Email"]) ? trim($input["Email"]) : null;
    $user_phone   = isset($input["Phone"]) ? trim($input["Phone"]) : null;
    $user_address = isset($input["Address"]) ? trim($input["Address"]) : null;

    if ($user_name && $user_email && $user_phone && $user_address) {
        require_once("./miniwoodker_conn_member.php");
        $stmt = $conn->prepare("UPDATE `member` SET `Email` = ?, `Phone` = ?, `Address` = ? WHERE `Username` = ?");
        $stmt->bind_param("ssss", $user_email, $user_phone, $user_address, $user_name);

        if ($stmt->execute()) {
            if ($stmt->affected_rows === 1) {
                respond(true, "會員資料更新成功", $stmt->affected_rows);
            } else {
                respond(false, "資料未變更或查無會員", $stmt->affected_rows);
            }
        } else {
            respond(false, "執行更新失敗：" . $stmt->error);
        }

        $stmt->close();
        $conn->close();
    } else {
        respond(false, "所有欄位皆為必填");
    }
}

function  delete_member()
{
    $input  =  get_input_data();
    $user_name   =  trim($input["Username"]);

    if (isset($input["Username"])) {

        if ($user_name) {
            require_once("miniwoodker_conn_member.php");

            $stmt  =  $conn->prepare("   DELETE  FROM  `member`   WHERE   `Username` = ?    ");
            $stmt->bind_param("s",     $user_name);

            if ($stmt->execute()) {
                if ($stmt->affected_rows  ===  1) {
                    respond(true,  "會員資料刪除成功");
                } else {
                    respond(false,  "找不到會員資料，無法刪除");
                }
            } else {
                respond(false,  "會員資料刪除失敗");
            }

        } else {
            respond(false,  "欄位為「空值」");
        }
    } else {
        respond(false,  "欄位不存在");
    }
}

if ($_SERVER["REQUEST_METHOD"]  ===  "POST") {
    $action   =   $_GET["action"];


    switch ($action) {
        case  "register":
            member_register();
            break;

        case  "login":
            member_login();
            break;

        case  "checkUID":
            member_checkUID();
            break;


        case  "update_member":
            update_member();
            break;

        case  "delete_member":
            delete_member();
            break;

        case  "getalldata":
            get_SQL_member();
            break;

        case  "getownerdata":
            get_SQL_getownerdata();
            break;

        case  "checkNAME":
            member_checkNAME();
            break;


        default:
            respond(false,  "GET之action資訊錯誤");
    }
}
