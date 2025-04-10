<?php
 
    $server      =  "sql102.infinityfree.com";
    $username    = "if0_38646795";
    $password    = "Nul00221166"; 
    $dbname      = "if0_38646795_db";
    $conn        =  mysqli_connect(  $server  ,  $username  ,  $password  ,  $dbname  )  ;

    if (  !$conn  ){      
                        echo   json_encode(   [  "statue" => false  ,  "message" => "連線失敗"  ]     ) ;    
                        exit ; }

?>

