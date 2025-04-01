<?php

// 前端/外部 資料 input
function  get_input_data()
{
    $data   =  file_get_contents("php://input");


    return  json_decode($data,  true);
}



// json格式 回復式                                                                                                                                
function  respond($state,  $message,  $login_data = null)
{
    echo    json_encode(["state" => $state,  "message"  =>  $message,  "login_data"  =>  $login_data]);
}



// 【會員註冊】函式                                                                                                                                   
function  member_register()
{
    $input  =  get_input_data();


    $user_name  =                     trim($input["user_Name"]);
    $pass_word  =  password_hash(trim($input["pass_Word"]),    PASSWORD_DEFAULT);
    $e_mail     =                     trim($input["e_Mail"]);
    $Phone     =                     trim($input["user_Phone"]);
    $Address     =                     trim($input["user_Address"]);

    // echo   $user_name  ,  $pass_word  ,  $e_mail  ;

    if (isset($input["user_Name"],  $input["pass_Word"],  $input["e_Mail"],  $input["user_Phone"],  $input["user_Address"])) {

        if ($user_name  &&  $pass_word  &&  $e_mail  &&  $Phone  &&  $Address) {
            require_once("miniwoodker_conn_member.php");

            $stmt  =  $conn->prepare("INSERT INTO  `member`( `Username`, `Password`, `Email`, `Phone`, `Address`)   VALUES (  ?  ,  ?  ,  ?  ,  ?  ,  ?  )");

            $stmt->bind_param("sssss",      $user_name,  $pass_word,  $e_mail,  $Phone,  $Address);

            // $stmt  ->  execute()  ;


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


// 會員登入函式 
function  member_login()
{
    $input  =  get_input_data();

    $user_name  =  trim($input["user_Name"]);
    $pass_word  =  trim($input["pass_Word"]);


    // echo   $user_name  ,  $pass_word    ;

    if (isset($input["user_Name"],  $input["pass_Word"])) {

        if ($user_name  &&  $pass_word) {
            require_once("miniwoodker_conn_member.php");



            $stmt  =  $conn->prepare("   SELECT    *    FROM `member` WHERE  `Username` =  ?   ");

            $stmt->bind_param("s",    $user_name);

            $stmt->execute();

            $result  =   $stmt->get_result();

            $row     =   $result->fetch_assoc();
            // echo  $row[ "Username" ] ;
            // echo  $row[ "Password" ] ;

            // $num     =   $result->num_rows;
            // echo  "<hr>"  .  $num    ;

            if ($result->num_rows === 1) {
                if (password_verify($pass_word,   $row["Password"])) {
                    // unset(   $row[ "Password" ]   )  ;
                    //   echo  $row[ "Password" ]  ;
                    //   echo  $row[ "Username" ] ;

                    // echo   json_encode(    [  "statue" => true   ,  "message"  =>  "登入成功"   ,  "login_data"  =>  $row  ]     )  ;  


                    // 自行 設定UID之驗證碼
                    $update_uid  =  substr(hash('sha256', time()),  10,  4)   .   substr(bin2hex(random_bytes(8)),  10,  4);


                    // 使用者  登入 時 -> 更新  資料庫之UID驗證碼
                    $update_stmt  =  $conn->prepare("   UPDATE   `member`   SET   `UID`=?    WHERE  `Username` =  ?   ");

                    $update_stmt->bind_param("ss",   $update_uid,    $user_name);

                    $update_stmt->execute();


                    if ($update_stmt->execute()) {
                        // 重新 select 登入帳號之資料庫欄位資料
                        $user_stmt  =  $conn->prepare("   SELECT    *    FROM `member` WHERE  `Username` =  ?   ");

                        $user_stmt->bind_param("s",    $user_name);

                        $user_stmt->execute();

                        $user_result  =   $user_stmt->get_result();

                        $user_row     =   $user_result->fetch_assoc();

                        // 刪除 登入帳號之資料庫「密碼」欄位資料                                                                                                                                                                                                                                                                                    
                        unset($user_row["Password"]);

                        // 輸出  登入帳號之json資訊                                     
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

// UID驗證碼辨識
function  member_checkUID()
{
    $input  =  get_input_data();


    $user_uid  =  trim($input["UID"]);

    // echo   $user_uid      ;

    if (isset($input["UID"])) {

        if ($user_uid) {
            require_once("miniwoodker_conn_member.php");



            $stmt  =  $conn->prepare("   SELECT    *    FROM `member` WHERE  `UID` =  ?   ");

            $stmt->bind_param("s",    $user_uid);

            $stmt->execute();



            $result  =   $stmt->get_result();

            $row     =   $result->fetch_assoc();
            // echo  $row[ "Username" ] ;
            // echo  $row[ "Password" ] ;
            // echo  $row[ "UID"      ] ;

            $num     =   $result->num_rows;
            // echo  "<hr>"  .  $num    ;



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




// 帳號重覆驗證
function  member_checkNAME()
{
    $input  =  get_input_data();


    $user_name  =  trim($input["user_Name"]);

    // echo   $user_uid      ;

    if (isset($input["user_Name"])) {

        if ($user_name) {
            require_once("miniwoodker_conn_member.php");



            $stmt  =  $conn->prepare("   SELECT    *    FROM `member` WHERE  `Username` =  ?   ");

            $stmt->bind_param("s",    $user_name);

            $stmt->execute();



            $result  =   $stmt->get_result();

            $row     =   $result->fetch_assoc();
            // echo  $row[ "Username" ] ;
            // echo  $row[ "Password" ] ;
            // echo  $row[ "UID"      ] ;

            $num     =   $result->num_rows;
            // echo  "<hr>"  .  $num    ;



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




// 取出 資料庫會員資料
function  get_SQL_member()
{
    // $input  =  get_input_data( ) ;
    require_once("miniwoodker_conn_member.php");


    $stmt  =  $conn->prepare("   SELECT    *    FROM   `member`      ");

    // $stmt  ->  bind_param(    "s"    ,    $user_name     )  ;

    $stmt->execute();
    // var_dump( $stmt  ->  execute()   ) ;


    $result  =   $stmt->get_result();
    // var_dump( $result ) ;

    $num     =   $result->num_rows;
    // echo  "<hr>"  .  $num    ;


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

// 取出 【自已】資料庫會員資料
function  get_SQL_getownerdata()
{
    $input  =  get_input_data();
    $UID    =  trim($input["UID"]);

    require_once("miniwoodker_conn_member.php");


    $stmt  =  $conn->prepare("   SELECT    *    FROM   `member`  Where  `UID`=?  ");

    $stmt->bind_param("s",    $UID);

    $stmt->execute();
    // var_dump( $stmt  ->  execute()   ) ;


    $result  =   $stmt->get_result();
    // var_dump( $result ) ;

    $num     =   $result->num_rows;
    // echo  "<hr>"  .  $num    ;


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


// 會員資料更新
function  update_member()
{
    $input  =  get_input_data();



    $user_name   =  trim($input["Username"]);
    $user_email  =  trim($input["Email"]);
    $user_phone  =  trim($input["Phone"]);
    $user_address  =  trim($input["Address"]);

    // echo   $user_uid      ;  echo   $user_email      ;

    // respond(   true    ,  "會員資料更新成功"   ,  $user_name   )  ;
    // respond(   true    ,  "會員資料更新成功"   ,  $user_email     )  ;


    if (isset($input["Username"],  $input["Email"],  $input["Phone"],  $input["Address"])) {

        if ($user_name && $user_email && $user_phone && $user_address) {
            require_once("./miniwoodker_conn_member.php");

            $stmt  =  $conn->prepare("UPDATE `member` SET `Email` = ?, `Phone` = ?, `Address` = ? WHERE `Username` = ?");


            $stmt->bind_param("ssss", $user_email, $user_phone, $user_address, $user_name);

            if ($stmt->execute()) {
                if ($stmt->affected_rows === 1) {
                    respond(true, "會員資料更新成功", $stmt->affected_rows);
                } else {
                    respond(false, "欄位「資料」相同，更新無效", $stmt->affected_rows);
                }
            } else {
                respond(false, "會員資料更新失敗");
            }

            $stmt->close();
            $conn->close();
        } else {
            respond(false, "欄位為「空值」");
        }
    } else {
        respond(false, "欄位不存在");
    }
}


// 會員資料刪除
function  delete_member()
{
    $input  =  get_input_data();

    $user_name   =  trim($input["Username"]);

    // echo   $user_uid      ;  

    if (isset($input["Username"])) {

        if ($user_name) {
            require_once("miniwoodker_conn_member.php");

            $stmt  =  $conn->prepare("   DELETE  FROM  `member`   WHERE   `Username` = ?    ");

            $stmt->bind_param("s",     $user_name);

            // $stmt  ->  execute()  ; 

            if ($stmt->execute()) {
                if ($stmt->affected_rows  ===  1) {
                    respond(true,  "會員資料刪除成功");
                } else {
                    respond(false,  "找不到會員資料，無法刪除");
                }
            } else {
                respond(false,  "會員資料刪除失敗");
            }

            // $stmt->close();
            // $conn->close();
        } else {
            respond(false,  "欄位為「空值」");
        }
    } else {
        respond(false,  "欄位不存在");
    }
}



// 伺服器Server  傳輸方式
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

        case  "checkNAME":
            member_checkNAME();
            break;

        default:
            respond(false,  "GET之action資訊錯誤");
    }
}
