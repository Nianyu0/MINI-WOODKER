<?php

function get_input_data()
{
    $data = file_get_contents("php://input");
    return json_decode($data, true);
}

function respond($state, $message, $data = null)
{
    $response = [
        "state" => $state,
        "message" => $message
    ];
    if ($data !== null) {
        $response["data"] = $data;
    }
    echo json_encode($response);
    exit;
}

function handleImageUpload($file)
{
    $fileName = time() . '_' . $file['name'];
    $uploadPath = 'uploads/' . $fileName;

    if (!file_exists('uploads')) {
        mkdir('uploads', 0777, true);
    }

    if (move_uploaded_file($file['tmp_name'], $uploadPath)) {
        return $uploadPath;
    }
    return false;
}

function get_products()
{

    require_once("miniwoodker_conn_member.php");

    $stmt  =  $conn->prepare("   SELECT * FROM `products`  ORDER BY created_at DESC   ");
    $stmt->execute();
    $result  =   $stmt->get_result();
    $num     =   $result->num_rows;

    if ($num > 0) {
        while ($row  =   $result->fetch_assoc()) {
            $SQL_data[]  =  $row;
        }
        respond(true,  "取出「資料庫」之商品資料",  $SQL_data);
    } else {
        respond(false,  "無法取出所有商品");
    }

    $stmt->close();
    $conn->close();

}

function addproduct()
{
    $input  =  get_input_data();

    $category   =  trim($input["Category"]);
    $name   =  trim($input["Name"]);
    $image   =  trim($input["Image"]);
    $content   =  trim($input["Content"]);
    $price   =  trim($input["Price"]);
    $stock   =  trim($input["Stock"]);


    if ($category != ""  && $name != ""  &&  $content != ""  &&  $price != ""  &&  $stock != ""  &&  $image != "") {
        require_once("miniwoodker_conn_member.php");

        $stmt  =  $conn->prepare("INSERT INTO `products`( `Category`,   `Name`,  `Content`, `Price`, `Stock`, `Image`) VALUES ( ?,?,?,?,?,? )");
        $stmt->bind_param("ssssss",   $category,  $name,  $content,  $price,  $stock,  $image);

        if ($stmt->execute()) {
            respond(true,  "新增成功",);
        } else {
            respond(false,  "新增失敗");
        }

        $stmt->close();
        $conn->close();
    } else {
        respond(false,  "欄位空白");
    }
}

function update_product()
{
    $input  =  get_input_data();

    $id         =  trim($input["Id"]);
    $category   =  trim($input["Category"]);
    $name       =  trim($input["Name"]);
    $content    =  trim($input["Content"]);
    $price      =  trim($input["Price"]);
    $stock      =  trim($input["Stock"]);

    require_once("miniwoodker_conn_member.php");

    $stmt  =  $conn->prepare("   UPDATE `products` SET  `Category`=?,`Name`=?,`Content`=?,`Price`=?,`Stock`=?  WHERE  `ID` = ?   ");
    $stmt->bind_param("sssssi",  $category,  $name,  $content,  $price,  $stock,  $id);

    if ($stmt->execute()) {
        if ($stmt->affected_rows  ===  1) {
            respond(true,  "商品資料更新成功");
        } else {
            respond(false,  "欄位「資料」相同，更新無效");
        }
    } else {
        respond(false,  "商品資料更新失敗");
    }

    $stmt->close();
    $conn->close();
}

function  img_turn()
{

    $filename = date("YmdHis") . "_" . $_FILES["file"]["name"];
    $location = "upload/" . $filename;    

    if (move_uploaded_file($_FILES["file"]["tmp_name"],  $location)) {
        $data_info  =  array();

        $data_info["state"]    =    true;
        $data_info["message"]  =   "檔案上傳成功";
        $data_info["name"]     =   $_FILES["file"]["name"];
        $data_info["location"] =   $location;
        $data_info["type"]     =   $_FILES["file"]["type"];
        $data_info["tmp_name"] =   $_FILES["file"]["tmp_name"];
        $data_info["size"]     =   $_FILES["file"]["size"];
        $data_info["error"]    =   $_FILES["file"]["error"];

        echo   json_encode($data_info);

       
    } else {
        $error_info  =  array();

        $error_info["state"]    =    false;
        $error_info["message"]  =   "檔案上傳失敗";
        $error_info["error"]    =   $_FILES["file"]["error"];

        echo   json_encode($error_info);
    }
}

function delete_product()
{
    $input  =  get_input_data();
    $Id   =  trim($input["Id"]);

    require_once("miniwoodker_conn_member.php");

    $stmt  =  $conn->prepare("   DELETE FROM `products`   WHERE   `ID` = ?    ");
    $stmt->bind_param("i",     $Id);


    if ($stmt->execute()) {
        if ($stmt->affected_rows  ===  1) {
            respond(true,  "商品資料刪除成功");
        } else {
            respond(false,  "找不到商品資料，無法刪除");
        }
    } else {
        respond(false,  "商品資料刪除失敗");
    }



    $stmt->close();
    $conn->close();

}

function getProductSales() {
    require_once("miniwoodker_conn_member.php");
    
    try {

        $sql = "SELECT p.Name, p.Id as Product_id, COALESCE(SUM(od.Quantity), 0) as TotalQuantity 
                FROM products p 
                LEFT JOIN order_details od ON p.Id = od.Product_id 
                GROUP BY p.Id, p.Name 
                ORDER BY TotalQuantity DESC";
                
        $stmt = $conn->prepare($sql);
        $stmt->execute();
        $result = $stmt->get_result();
        
        $data = array();
        while ($row = $result->fetch_assoc()) {
            $data[] = $row;
        }
        
        echo json_encode([
            'state' => true,
            'data' => $data
        ]);
        
        $stmt->close();
        $conn->close();
        
    } catch(Exception $e) {
        echo json_encode([
            'state' => false,
            'message' => '無法獲取產品銷售數據: ' . $e->getMessage()
        ]);
    }
}


if ($_SERVER["REQUEST_METHOD"] === "POST" || $_SERVER["REQUEST_METHOD"] === "GET") {
    $action = $_GET["action"] ?? '';

    switch ($action) {
        case 'getProducts':
            get_products();
            break;

        case 'addProduct':
            addproduct();
            break;

        case 'updateProduct':
            update_product();
            break;

        case 'deleteProduct':
            delete_product();
            break;

        case 'img_turn':
            img_turn();
            break;

        case 'getProductSales':
            getProductSales();
            break;

        default:
            respond(false, "未知操作");
    }
}


