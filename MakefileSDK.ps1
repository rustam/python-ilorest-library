$START_DIR = "$(get-location)"
$product_version = $Env:MTX_PRODUCT_VERSION
if (!"$product_version") {
    $product_version = "9.9.9.9"
}

$build_number = $Env:MTX_BUILD_NUMBER
if (!"$build_number") {
    $build_number = "999"
}

if( Test-Path $START_DIR\lessmsi ) { Remove-Item $START_DIR\lessmsi -Recurse -Force }
New-Item -ItemType directory -Path .\lessmsi
& 7z x -y -olessmsi .\packaging\lessmsi\lessmsi-v1.3.zip
if ( $LastExitCode ) { exit 1 }

if( Test-Path $START_DIR\python-2.7.10.amd64 ) { Remove-Item $START_DIR\python-2.7.11.amd64 -Recurse -Force }
& $START_DIR\lessmsi\lessmsi x .\packaging\python\python-2.7.11.amd64.msi
if ( $LastExitCode ) { exit 1 }

$Env:PYTHONPATH="$START_DIR\src"
$PYTHON_AMD64 = "${START_DIR}\python-2.7.11.amd64\SourceDir\python.exe"

Set-Location -Path $START_DIR

Function InstallPythonModule($python, $name, $version) {
    Set-Location -Path "${START_DIR}"
    if( Test-Path .\${name} ) { Remove-Item .\${name} -Recurse -Force }
    New-Item -ItemType directory -Path "${START_DIR}\${name}"
    & 7z x -y "-o${name}" .\packaging\ext\${name}-${version}.tar.gz
    & 7z x -y "-o${name}" "${START_DIR}\${name}\dist\${name}-${version}.tar"
    Set-Location -Path "${START_DIR}\${name}\${name}-${version}"
    & $python setup.py install
    Set-Location -Path "${START_DIR}"
}

InstallPythonModule "$PYTHON_AMD64" "setuptools" "2.2"

Set-Location -Path ${START_DIR}
& $PYTHON_AMD64 setup.py "sdist" "--formats=zip"
Copy-Item ".\dist\*" "$Env:MTX_COLLECTION_PATH"





