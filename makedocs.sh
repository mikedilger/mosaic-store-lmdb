#!/bin/bash

cargo doc --no-deps
echo "<meta http-equiv=\"refresh\" content=\"0; url=mosaic_core/index.html\">" > target/doc/index.html
rm -rf ./docs
mv target/doc ./docs
