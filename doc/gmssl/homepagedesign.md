# GmSSL Homepage Design

This document introduces the purpose and design of the GmSSL project homepage, which is located at http://gmssl.org and http://www.gmssl.org.

## Rules

1. To simply the maintenance, the GmSSL project website is a single page website. Never use complicated frameworks, theme and dynamic pages except for the default GitHub page generator.
2. The homepage is written in both Chinese and English. But the documents will be major written in English.
3. More information is provided by the GitHub project wiki and the documents (in Markdown or HTML) in the source code.
4. Do not duplicate documents. For example, manuals are provided with HTML or Markdown generated from the POD files. These duplicated Markdown or HTML should not be kept in the source code. For the files generated from POD files, the homepage repository is a better place than the wiki.
5. Source code only include documents written in English and in text format (txt, md, pod or html). Never include binary files like PDF files in source code.
6. Never use Doxygen comments on master and develop branch source code because the maintenance is very hard. If such documents or manuals are required, create a new repository with only the header files to add the comments.
7. Add documents to source code instead of GitHub wiki. The wiki is not very popular, and without the default support of git logs.
8. **NEVER** provide binary downloads in our homepage.

## Contents

The content of GmSSL project homepage is referenced to the OpenSSL homepage and http://redis.cn. The following contents should be included:

* Introduction of the project.
* Download
* Manuals
* Standards
* An architecture graph
* Community.
* Commands
* To be added …

## Tips

* The `pod2html` command in Linux support style sheets.
* GitHub provide good rendering on Markdown documents.

------------------------------------------------------
Copyright 2016 The GmSSL Project. All Rights Reserved.
