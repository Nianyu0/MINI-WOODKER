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


function  addToCart(){  
    $input = get_input_data();

    $userId = isset($input['User_id']) ? intval($input['User_id']) : null;
    $productId = isset($input['Product_id']) ? intval($input['Product_id']) : null;
    $quantity = isset($input['Quantity']) ? intval($input['Quantity']) : null;
    $price = isset($input['Price']) ? intval($input['Price']) : null;


    if ($userId === null || $productId === null || $quantity === null || $price === null) {
        respond(false, "錯誤!");
        return;
    }

    if ($userId <= 0 || $productId <= 0 || $quantity <= 0 || $price <= 0) {
        respond(false, "錯誤!");
        return;
    }

    require_once("http://nianyu0.rf.gd/miniwoodker_conn_member.php");

    try {
        $checkStmt = $conn->prepare("SELECT Stock, Name FROM products WHERE Id = ?");
        $checkStmt->bind_param("i", $productId);
        $checkStmt->execute();
        $result = $checkStmt->get_result();
        $product = $result->fetch_assoc();

        if (!$product) {
            throw new Exception("商品不存在");
        }

        if ($product['Stock'] <= 0) {
            throw new Exception("商品 {$product['Name']} 已售罄");
        }

        if ($quantity > $product['Stock']) {
            throw new Exception("商品 {$product['Name']} 庫存不足，剩餘 {$product['Stock']} 件");
        }

        $cartStmt = $conn->prepare("SELECT Quantity FROM cart WHERE User_id = ? AND Product_id = ?");
        $cartStmt->bind_param("ii", $userId, $productId);
        $cartStmt->execute();
        $cartResult = $cartStmt->get_result();
        $cartItem = $cartResult->fetch_assoc();

        if ($cartItem) {
            $totalQuantity = $cartItem['Quantity'] + $quantity;
            if ($totalQuantity > $product['Stock']) {
                throw new Exception("商品 {$product['Name']} 庫存不足，購物車已有 {$cartItem['Quantity']} 件，庫存剩餘 {$product['Stock']} 件");
            }
        }

        $stmt = $conn->prepare("INSERT INTO `cart` (`User_id`, `Product_id`, `Quantity`, `Price`) VALUES (?, ?, ?, ?)");
        
        if (!$stmt) {
            throw new Exception("準備SQL語句失敗: " . $conn->error);
        }

        $stmt->bind_param("iiii", $userId, $productId, $quantity, $price);

        if ($stmt->execute()) {
            respond(true, "新增成功");
        } else {
            throw new Exception("執行SQL語句失敗: " . $stmt->error);
        }
    } catch (Exception $e) {
        error_log("加入購物車錯誤: " . $e->getMessage());
        respond(false, $e->getMessage());
    } finally {
        if (isset($stmt)) {
            $stmt->close();
        }
        if (isset($conn)) {
            $conn->close();
        }
    }
}

function getCart() {
    $input = get_input_data();
    $userId = $input['User_id'];

    if ($userId != "") {
        require_once("http://nianyu0.rf.gd/miniwoodker_conn_member.php");

        $stmt = $conn->prepare("
            SELECT 
                c.Product_id,
                c.Quantity,
                c.Price,
                p.Name,
                p.Image
            FROM cart c 
            LEFT JOIN products p ON c.Product_id = p.Id
            WHERE c.User_id = ?
        ");
        
        if (!$stmt) {
            error_log("Prepare failed: " . $conn->error);
            respond(false, "準備查詢失敗");
            return;
        }

        $stmt->bind_param("i", $userId);

        if ($stmt->execute()) {
            $result = $stmt->get_result();
            $cart_items = array();
            
            while ($row = $result->fetch_assoc()) {
                $cart_items[] = $row;
            }
            
            respond(true, "獲取購物車成功", $cart_items);
        } else {
            error_log("Execute failed: " . $stmt->error);
            respond(false, "獲取購物車失敗");
        }

        $stmt->close();
        $conn->close();
    } else {
        respond(false, "會員不能為空");
    }
}

function removeItem() {
    $input = get_input_data();
    $userId = $input['User_id'];
    $productId = $input['Product_id'];

    if ($userId && $productId) {
        require_once("http://nianyu0.rf.gd/miniwoodker_conn_member.php");

        $stmt = $conn->prepare("DELETE FROM cart WHERE User_id = ? AND Product_id = ?");
        $stmt->bind_param("ii", $userId, $productId);

        if ($stmt->execute()) {
            respond(true, "商品已刪除");
        } else {
            respond(false, "刪除失敗");
        }

        $stmt->close();
        $conn->close();
    } else {
        respond(false, "錯誤!");
    }
}

function checkout() {
    $input = get_input_data();
    $userId = $input['User_id'];

    if ($userId) {
        require_once("http://nianyu0.rf.gd/miniwoodker_conn_member.php");
        
        try {
            $conn->begin_transaction();
            
            $checkStmt = $conn->prepare("
                SELECT c.Product_id, c.Quantity, p.Stock, p.Name
                FROM cart c 
                LEFT JOIN products p ON c.Product_id = p.Id 
                WHERE c.User_id = ?
            ");
            $checkStmt->bind_param("i", $userId);
            $checkStmt->execute();
            $result = $checkStmt->get_result();
            
            while ($item = $result->fetch_assoc()) {
                if ($item['Stock'] === null) {
                    throw new Exception("購物車中存在無效商品，請先刪除");
                }
                if ($item['Quantity'] > $item['Stock']) {
                    throw new Exception("商品 {$item['Name']} 庫存不足，剩餘 {$item['Stock']} 件");
                }
            }
            
            $stmt = $conn->prepare("INSERT INTO orders (User_id, Order_date, Status) VALUES (?, NOW(), '處理中')");
            $stmt->bind_param("i", $userId);
            $stmt->execute();
            $orderId = $conn->insert_id;
            
            $stmt = $conn->prepare("
                SELECT Product_id, Quantity, Price 
                FROM cart 
                WHERE User_id = ?
            ");
            $stmt->bind_param("i", $userId);
            $stmt->execute();
            $cartResult = $stmt->get_result();
            
            $updateStockStmt = $conn->prepare("
                UPDATE products 
                SET Stock = Stock - ? 
                WHERE Id = ?
            ");
            
            $orderDetailStmt = $conn->prepare("
                  INSERT INTO order_details (Order_id, Product_id, Quantity, Price, Subtotal)
                  VALUES (?, ?, ?, ?, ?)
            ");
            
            if ($cartResult->num_rows === 0) {
                error_log("結帳失敗!");
              }

            while ($item = $cartResult->fetch_assoc()) {
     
                $updateStockStmt->bind_param("ii", 
                    $item['Quantity'],
                    $item['Product_id']
                );
                $updateStockStmt->execute();
                
                $subtotal = $item['Price'] * $item['Quantity'];
                $orderDetailStmt->bind_param("iiiid",
                $orderId,
                $item['Product_id'],
                $item['Quantity'],
                $item['Price'],
                $subtotal
                );
                $orderDetailStmt->execute();
            }
            
            $stmt = $conn->prepare("DELETE FROM cart WHERE User_id = ?");
            $stmt->bind_param("i", $userId);
            $stmt->execute();
   
            $conn->commit();
            
            respond(true, "結帳成功", ["order_id" => $orderId]);
            
        } catch (Exception $e) {
            $conn->rollback();
            respond(false, $e->getMessage());
        }
        
        $conn->close();
    } else {
        respond(false, "會員不能為空");
    }
}

function getOrders() {
    $input = get_input_data();
    $userId = $input['User_id'] ?? null;
    $type = $input['type'] ?? null;

    require_once("http://nianyu0.rf.gd/miniwoodker_conn_member.php");

    if ($type === 'list') {
        $sql = "
            SELECT 
                o.Id as Order_id,
                o.Order_date,
                o.Status,
                m.Username,
                CAST(SUM(od.Quantity * od.Price) AS DECIMAL(10,2)) as Total_Amount,
                COUNT(od.Id) as Items_Count
            FROM orders o 
            JOIN order_details od ON o.Id = od.Order_id
            JOIN member m ON o.User_id = m.ID
            GROUP BY o.Id, o.Order_date, o.Status, m.Username
            ORDER BY o.Order_date DESC
        ";
        
        $result = $conn->query($sql);
        
        if (!$result) {
            error_log("查詢失敗 " . $conn->error);
            respond(false, "查詢失敗");
            return;
        }
        
        $orders = array();
        while ($row = $result->fetch_assoc()) {
            $row['Total_Amount'] = floatval($row['Total_Amount']);
            $orders[] = $row;
        }
        
        respond(true, "獲取訂單列表成功", $orders);
        return;
    }

    if ($userId) {
        $sql = "
            SELECT 
            o.Id as Order_id,
            o.Order_date,
            o.Status,
            GROUP_CONCAT(p.Name SEPARATOR ', ') AS Products,
            SUM(od.Quantity) AS Total_Quantity,
            SUM(od.Quantity * od.Price) AS Total_Amount
            FROM orders o
            JOIN order_details od ON o.Id = od.Order_id
            JOIN products p ON od.Product_id = p.Id
            WHERE o.User_id = (SELECT ID FROM member WHERE UID = ?)
            GROUP BY o.Id, o.Order_date, o.Status
            ORDER BY o.Order_date DESC
        ";
        
        $stmt = $conn->prepare($sql);
        
        if (!$stmt) {
            error_log("準備查詢失敗: " . $conn->error);
            respond(false, "準備查詢失敗");
            return;
        }

        $stmt->bind_param("s", $userId);

        if ($stmt->execute()) {
            $result = $stmt->get_result();
            $orders = array();
            
            while ($row = $result->fetch_assoc()) {
                $orders[] = $row;
            }
            
            if (count($orders) > 0) {
                respond(true, "獲取訂單列表成功", $orders);
            } else {
                respond(false, "暫無訂單記錄");
            }
        } else {
            error_log("執行查詢失敗: " . $stmt->error);
            respond(false, "獲取訂單失敗");
        }

        $stmt->close();
    } else {
        respond(false, "參數錯誤");
    }
    
    $conn->close();
}

function getOrderDetail() {
    $input = get_input_data();
    $orderId = $input['Order_id'];

    if ($orderId) {
        require_once("http://nianyu0.rf.gd/miniwoodker_conn_member.php");

        $sql = "
            SELECT 
                o.Id as Order_id,
                o.Order_date,
                o.Status,
                m.Username,
                m.Phone,
                m.Address,
                od.Quantity,
                od.Price,
                (od.Quantity * od.Price) as Subtotal,
                GROUP_CONCAT(
                    CASE od.Product_id
                        WHEN 1 THEN 'MINI WOODKER 全套組'
                        WHEN 2 THEN 'MINI WOODKER 手工具組'
                        WHEN 3 THEN 'MINI WOODKER 機台'
                        WHEN 4 THEN 'MINI WOODKER 模板'
                        WHEN 5 THEN 'MINI WOODKER 圓鋸機頭'
                        WHEN 6 THEN 'MINI WOODKER 線鋸機頭'
                        WHEN 7 THEN 'MINI WOODKER 修邊機頭'
                        WHEN 8 THEN 'MINI WOODKER 鑽孔機頭'
                        ELSE '未命名商品'
                    END
                    SEPARATOR ', '
                ) as Products,
                SUM(od.Quantity * od.Price) as Total_Amount
            FROM orders o 
            JOIN order_details od ON o.Id = od.Order_id
            JOIN member m ON o.User_id = m.ID
            WHERE o.Id = ?
            GROUP BY o.Id, o.Order_date, o.Status, m.Username, m.Phone, m.Address, od.Quantity, od.Price
        ";
        
        $stmt = $conn->prepare($sql);
        
        if (!$stmt) {
            error_log("Prepare failed: " . $conn->error);
            respond(false, "準備查詢失敗");
            return;
        }

        $stmt->bind_param("i", $orderId);

        if ($stmt->execute()) {
            $result = $stmt->get_result();
            $order = $result->fetch_assoc();
            
            if ($order) {
                respond(true, "獲取訂單詳情成功", $order);
            } else {
                respond(false, "找不到該訂單");
            }
        } else {
            error_log("Execute failed: " . $stmt->error);
            respond(false, "執行查詢失敗");
        }

        $stmt->close();
        $conn->close();
    } else {
        respond(false, "訂單編號不能為空");
    }
}

function updateOrderStatus() {
    $input = get_input_data();
    $orderId = $input['Order_id'];
    $status = $input['Status'];

    if ($orderId && $status) {
        require_once("http://nianyu0.rf.gd/miniwoodker_conn_member.php");

        $stmt = $conn->prepare("UPDATE orders SET Status = ? WHERE Id = ?");
        
        if (!$stmt) {
            error_log("Prepare failed: " . $conn->error);
            respond(false, "準備更新失敗");
            return;
        }

        $stmt->bind_param("si", $status, $orderId);

        if ($stmt->execute()) {
            respond(true, "訂單狀態更新成功");
        } else {
            error_log("Execute failed: " . $stmt->error);
            respond(false, "更新失敗");
        }

        $stmt->close();
        $conn->close();
    } else {
        respond(false, "訂單編號和狀態不能為空");
    }
}

function getRevenue() {
    require_once("http://nianyu0.rf.gd/miniwoodker_conn_member.php");
    
    try {
        $period = isset($_GET['period']) ? $_GET['period'] : 'day';
        
        if ($period === 'day') {

            $sql = "
                SELECT 
                    dates.date,
                    COALESCE(SUM(od.Price * od.Quantity), 0) as total_revenue
                FROM (
                    SELECT CURDATE() - INTERVAL (a.a + (10 * b.a) + (100 * c.a)) DAY as date
                    FROM (SELECT 0 as a UNION ALL SELECT 1 UNION ALL SELECT 2 UNION ALL SELECT 3 UNION ALL SELECT 4 UNION ALL SELECT 5 UNION ALL SELECT 6 UNION ALL SELECT 7 UNION ALL SELECT 8 UNION ALL SELECT 9) as a
                    CROSS JOIN (SELECT 0 as a UNION ALL SELECT 1 UNION ALL SELECT 2 UNION ALL SELECT 3 UNION ALL SELECT 4 UNION ALL SELECT 5 UNION ALL SELECT 6 UNION ALL SELECT 7 UNION ALL SELECT 8 UNION ALL SELECT 9) as b
                    CROSS JOIN (SELECT 0 as a UNION ALL SELECT 1 UNION ALL SELECT 2 UNION ALL SELECT 3 UNION ALL SELECT 4 UNION ALL SELECT 5 UNION ALL SELECT 6 UNION ALL SELECT 7 UNION ALL SELECT 8 UNION ALL SELECT 9) as c
                ) dates
                LEFT JOIN orders o ON DATE(o.Order_date) = dates.date
                LEFT JOIN order_details od ON o.Id = od.Order_id
                WHERE dates.date >= CURDATE() - INTERVAL 29 DAY
                    AND dates.date <= CURDATE()
                GROUP BY dates.date
                ORDER BY dates.date ASC";
        } else {
            $sql = "SELECT 
                    DATE_FORMAT(o.Order_date, '%Y-%m') as date,
                    SUM(od.Price * od.Quantity) as total_revenue
                FROM orders o
                JOIN order_details od ON o.Id = od.Order_id
                GROUP BY DATE_FORMAT(o.Order_date, '%Y-%m')
                ORDER BY date DESC
                LIMIT 12";
        }
        
        $result = $conn->query($sql);
        
        if (!$result) {
            throw new Exception("查詢執行失敗: " . $conn->error);
        }
        
        $data = array();
        
        while ($row = $result->fetch_assoc()) {
            $data[] = array(
                'date' => $row['date'],
                'revenue' => floatval($row['total_revenue'])
            );
        }

        if (count($data) > 0) {
            respond(true, "成功獲取營收數據", $data);
        } else {
            respond(false, "沒有找到營收數據");
        }
        
    } catch (Exception $e) {
        error_log("營收數據獲取錯誤: " . $e->getMessage());
        respond(false, "獲取營收數據時發生錯誤: " . $e->getMessage());
    } finally {
        if (isset($conn)) {
            $conn->close();
        }
    }
}

function updateQuantity() {
    $input = get_input_data();
    $userId = intval($input['User_id']);
    $productId = intval($input['Product_id']);
    $quantity = intval($input['Quantity']);

    error_log("更新購物車: User_id=" . $userId . ", Product_id=" . $productId . ", Quantity=" . $quantity);

    if ($userId && $productId && $quantity > 0) {
        require_once("http://nianyu0.rf.gd/miniwoodker_conn_member.php");

        try {
            $stmt = $conn->prepare("
                SELECT Price/Quantity as UnitPrice 
                FROM cart 
                WHERE User_id = ? AND Product_id = ?
            ");
            
            if (!$stmt) {
                error_log("準備查詢失敗: " . $conn->error);
                respond(false, "準備查詢失敗");
                return;
            }

            $stmt->bind_param("ii", $userId, $productId);
            
            if (!$stmt->execute()) {
                error_log("執行查詢失敗: " . $stmt->error);
                respond(false, "執行查詢失敗");
                return;
            }

            $result = $stmt->get_result();
            $row = $result->fetch_assoc();
            
            if ($row) {
                $unitPrice = floatval($row['UnitPrice']);
                $newPrice = $unitPrice * $quantity;
                
                error_log("更新價格: UnitPrice=" . $unitPrice . ", NewPrice=" . $newPrice);
                

                $updateStmt = $conn->prepare("
                    UPDATE cart 
                    SET Quantity = ?, Price = ? 
                    WHERE User_id = ? AND Product_id = ?
                ");
                
                if (!$updateStmt) {
                    error_log("準備更新失敗: " . $conn->error);
                    respond(false, "準備更新失敗");
                    return;
                }

                $updateStmt->bind_param("idii", $quantity, $newPrice, $userId, $productId);
                
                if ($updateStmt->execute()) {
                    if ($updateStmt->affected_rows > 0) {
                        respond(true, "數量更新成功");
                    } else {
                        respond(false, "沒有更新任何數據");
                    }
                } else {
                    error_log("執行更新失敗: " . $updateStmt->error);
                    respond(false, "更新失敗");
                }
                $updateStmt->close();
            } else {
                error_log("找不到購物車項目");
                respond(false, "找不到購物車項目");
            }
            
            $stmt->close();
        } catch (Exception $e) {
            error_log("更新購物車發生錯誤: " . $e->getMessage());
            respond(false, "系統錯誤");
        } finally {
            if (isset($conn)) {
                $conn->close();
            }
        }
    } else {
        error_log("參數錯誤: User_id=" . $userId . ", Product_id=" . $productId . ", Quantity=" . $quantity);
        respond(false, "錯誤!");
    }
}

if ($_SERVER["REQUEST_METHOD"] === "POST" || $_SERVER["REQUEST_METHOD"] === "GET") {
    $action = $_GET["action"] ?? '';

    switch ($action) {
        case 'addToCart':
            addToCart();
            break;
        case 'getCart':
            getCart();
            break;
        case 'removeItem':
            removeItem();
            break;
        case 'checkout':
            checkout();
            break;
        case 'getOrders':
            getOrders();
            break;
        case 'getOrderDetail':
            getOrderDetail();
            break;
        case 'updateOrderStatus':
            updateOrderStatus();
            break;
        case 'getRevenue':
            getRevenue();
            break;
        case 'updateQuantity':
            updateQuantity();
            break;
        default:
            respond(false, "未知操作");
    }
}
