<?php
 
    $server      =  "localhost";
    $username    =  "admin";
    $password    =  "789456";
    $dbname      =  "miniwoodker";

    $conn  =  mysqli_connect(  $server  ,  $username  ,  $password  ,  $dbname  )  ;

    if (  !$conn  ){      
                        echo   json_encode(   [  "statue" => false  ,  "message" => "連線失敗"  ]     ) ;    
                        exit ; }

    
?>

