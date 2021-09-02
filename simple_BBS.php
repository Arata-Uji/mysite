<!--
新しく使った知識
・htmlspecialchars関数
https://flytech.work/blog/7620/
・パスワードの暗号化と認証
https://qiita.com/wakahara3/items/792943c1e0ed7a87e1ef
・パスワードの入力制限、preg_match関数
https://qiita.com/mpyw/items/886218e7b418dfed254b
https://techacademy.jp/magazine/11402
・HTML、type='number'で負の数を許可しない
https://www.it-mure.jp.net/ja/html/input-type-number%E3%81%8C%E8%B2%A0%E3%81%AE%E5%80%A4%E3%81%AB%E3%81%AA%E3%82%8B%E3%81%AE%E3%82%92%E9%98%B2%E3%81%90%E6%96%B9%E6%B3%95%E3%81%AF%E3%81%82%E3%82%8A%E3%81%BE%E3%81%99%E3%81%8B%EF%BC%9F/940044235/
・PHPのHTML埋め込み
https://www.flatflag.nir87.com/foreach-294#endforeachHTML
-->

<?php
    session_start();
    $num_ed = '';
    $name_ed = '';
    $comment_ed = '';
    $pass_ed = '';
    
    $dsn = 'データベース名'; 
    $user = 'ユーザ名';
    $pass = 'パスワード';
    $pdo = new PDO($dsn, $user, $pass, array(PDO::ATTR_ERRMODE => PDO::ERRMODE_WARNING)); //データベースに接続。カラムはid,name,comment,date,password

    $sql = 'CREATE TABLE IF NOT EXISTS tbtest' //tbtestというテーブルが存在しなければ、tebestというテーブルを作る
    .'('
    .'id INT AUTO_INCREMENT PRIMARY KEY,'
    .'name CHAR(32),' 
    .'comment TEXT,'
    .'date DATETIME,'
    .'password CHAR(60)'
    .');';
    $stmt = $pdo->query($sql);

    function h($str) { //特殊文字変換を変換する関数
        return htmlspecialchars($str, ENT_QUOTES, "UTF-8"); 
    }

    function id_ver($id) { //投稿番号認証の関数
        global $pdo;
        $sql = 'SELECT id FROM tbtest WHERE id = :id';
        $stmt = $pdo->prepare($sql);
        $stmt->bindParam(':id', $id, PDO::PARAM_INT);
        $stmt->execute();
        list($id_data) = $stmt->fetch();
            
        if(isset($id_data)) {
            return TRUE;
        
        } else {
            return FALSE;
        }
    }

    function pass_ver($id, $pass) { //パスワード認証の関数
        global $pdo;
        $sql = 'SELECT password FROM tbtest WHERE id = :id';
        $stmt = $pdo->prepare($sql);
        $stmt->bindParam(':id', $id, PDO::PARAM_INT);
        $stmt->execute();
        list($pass_data) = $stmt->fetch();
        
        if(password_verify($pass, $pass_data)) {
            return TRUE;
        
        } else {
            return FALSE;
        }
    }
    
    if(isset($_REQUEST['token']) && isset($_SESSION['token']) && ($_REQUEST['token'] == $_SESSION['token'])) { //トークンの照合

        if(isset($_POST['name']) && isset($_POST['comment']) && isset($_POST['pass'])) { //追加処理・編集追加処理
            
            if($_POST['name'] != '' && $_POST['comment'] != '' && $_POST['pass'] != '') { //空白で送信されていたら「未入力項目があります」と表示
                $name = h($_POST['name']);
                $comment = h($_POST['comment']);
                $date = date('Y/m/d H:i:s');
                
                if(preg_match('/\A[a-z\d]{3,30}+\z/i', $_POST['pass'])) { //パスワードが半角英数字3〜30文字の条件を満たすか確認
                    $pass = password_hash($_POST['pass'], PASSWORD_DEFAULT); //パスワードを暗号化

                    if($_POST['num_ed']) { //編集追加
                        $id = $_POST['num_ed'];
                        $sql = 'UPDATE tbtest SET name = :name, comment = :comment, date = :date, password = :password WHERE id = :id'; //UPDATEで更新。WHEREで更新する行を指定。SETで更新する内容を指定
                        $stmt = $pdo->prepare($sql);
                        $stmt->bindParam(':id', $id, PDO::PARAM_INT);           //プレースホルダー（:id）に$idをバインド
                        $stmt->bindParam(':name', $name, PDO::PARAM_STR);       //プレースホルダー（:name）に$nameをバインド
                        $stmt->bindParam(':comment', $comment, PDO::PARAM_STR); //プレースホルダー（:comment）に$commentをバインド
                        $stmt->bindParam(':date', $date, PDO::PARAM_STR);       //プレースホルダー（:date）に$dateをバインド
                        $stmt->bindParam(':password', $pass, PDO::PARAM_STR);   //プレースホルダー（:password）に$passをバインド
                        $stmt->execute();
                        echo '編集しました';
                        
                    } else { //通常の追加
                        $sql = 'INSERT INTO tbtest (name, comment, date, password) VALUES (:name, :comment, :date, :password)';
                        $stmt = $pdo->prepare($sql);
                        $stmt->bindParam(':name', $name, PDO::PARAM_STR);       //プレースホルダー（:name）に$nameをバインド
                        $stmt->bindParam(':comment', $comment, PDO::PARAM_STR); //プレースホルダー（:comment）に$commentをバインド
                        $stmt->bindParam(':date', $date, PDO::PARAM_STR);       //プレースホルダー（:date）に$dateをバインド
                        $stmt->bindParam(':password', $pass, PDO::PARAM_STR);   //プレースホルダー（:passwoed）に$passをバインド
                        $stmt->execute();
                        echo '投稿しました';
                    }

                } else {
                    echo 'パスワードは半角英数字の3〜30文字で入力してください';
                }

            } else {
                echo '未入力項目があります';
            }
        
        } elseif(isset($_POST['delete']) && isset($_POST['pass'])) { //削除機能

            if($_POST['delete'] != '' && $_POST['pass'] != '') { //空白で送信されていたら「未入力項目があります」と表示
                $id = $_POST['delete'];
            
                if(id_ver($id)) { //投稿番号認証
                    $pass = $_POST['pass'];
                    
                    if(pass_ver($id, $pass)) { //パスワード認証
                        $sql = 'DELETE FROM tbtest WHERE id = :id'; //削除処理
                        $stmt = $pdo->prepare($sql);
                        $stmt->bindParam(':id', $id, PDO::PARAM_INT);
                        $stmt->execute();
                        $sql = 'ALTER TABLE tbtest DROP COLUMN id';
                        $stmt = $pdo->query($sql);
                        $sql = 'ALTER TABLE tbtest ADD id INT PRIMARY KEY AUTO_INCREMENT FIRST'; //idカラムを再度作成
                        $stmt = $pdo->query($sql);
                        echo '削除しました';
            
                    } else {
                        echo 'パスワードが一致しません';
                    }

                } else {
                    echo 'この投稿番号は存在しません';
                }
            
            } else {
                echo '未入力項目があります';
            }

        } elseif(isset($_POST['edit']) && isset($_POST['pass'])) { //編集機能

            if($_POST['edit'] != '' && $_POST['pass'] != '') { //空白で送信されていたら「未入力項目があります」と表示
                $id = $_POST['edit'];
            
                if(id_ver($id)) { //投稿番号認証
                    $pass = $_POST['pass'];
                    
                    if(pass_ver($id, $pass)) { //パスワード認証
                        $sql = 'SELECT id, name, comment FROM tbtest WHERE id = :id'; //入力欄に表示させるための処理
                        $stmt = $pdo->prepare($sql);
                        $stmt->bindParam(':id', $id, PDO::PARAM_INT);
                        $stmt->execute();
                        list($num_ed, $name_ed, $comment_ed) = $stmt->fetch();
                        $pass_ed = $pass;
                        echo '編集してください';

                    } else { 
                        echo 'パスワードが一致しません';
                    }

                } else {
                    echo 'この投稿番号は存在しません';
                }
            
            } else {
                echo '未入力項目があります';
            }
        }
    }

    echo '<br>';
    $token = md5(uniqid(rand(), true));
    $_SESSION['token'] = $token;
?>
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>mission_5-1</title>
</head>
<body>
    <h4>投稿フォーム</h4>
    <form action="" method="post">
        <input type="hidden" name="token" value="<?php echo $token; ?>">
        <input type="hidden" name="num_ed" value="<?php echo $num_ed; ?>">
        <input type="text" name="name" placeholder="名前" value="<?php echo $name_ed; ?>">
        <input type="text" name="comment" placeholder="コメント" value="<?php echo $comment_ed; ?>">
        <input type="password" name="pass" placeholder="パスワード" value="<?php echo $pass_ed; ?>">
        <input type="submit" name="submit">
    </form>
    <h4>削除フォーム</h4>
    <form action="" method="post">
        <input type="hidden" name="token" value="<?php echo $token; ?>">
        <input type="number" name="delete" min="1" placeholder="削除対象番号">
        <input type="password" name="pass" placeholder="パスワード">
        <input type="submit" name="submit" value="削除">
    </form>
    <h4>編集フォーム</h4>
    <form action="" method="post">
        <input type="hidden" name="token" value="<?php echo $token; ?>">
        <input type="number" name="edit" min="1" placeholder="編集対象番号">
        <input type="password" name="pass" placeholder="パスワード">
        <input type="submit" name="submit" value="編集">
    </form>
    <?php
        $sql = 'SELECT * FROM tbtest';
        $stmt = $pdo->query($sql);
        $res = $stmt->fetchAll(PDO::FETCH_ASSOC); //fetchAllでデータベースからの取得データをすべて配列として代入
    ?>
    <?php foreach($res as $row): ?> <!--取得結果を表示-->
        <p>
        <?php echo $row['id'].', '.$row['name'].', '.$row['comment'].', '.$row['date'].'<br>'.'<hr>'; ?>
        </p>
    <?php endforeach ?>
    <?php $pdo = NULL; ?>
</body>
</html>