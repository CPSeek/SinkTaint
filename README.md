# SinkTaint
This is a prototype of a taint-style vulnerability discovery method in embedded firmware (SinkTaint), a precise and novel method that employs backtracking and constraint analysis to achieve high precision. 



<img src=sinktaint-workflow.jpg width=95% />

* Our method is based on [SaTC](https://github.com/NSSL-SJTU/SaTC) and [Karonte](https://github.com/ucsb-seclab/karonte). We would like to express our gratitude to the authors for opening source their work.
# Running example
```bash
# directory: sinktaint_front
python3 sinktaint.py -d /home/sinktaint/firmware/XR300/squashfs-root/ -o ~/output/XR300/ --ghidra_script=ref2sink_bof
# directory: taint_check
python3 sinktaint_main.py /home/sinktaint/output/XR300/ghidra_extract_result/httpd/httpd /home/sinktaint/output/XR300/ghidra_extract_result/httpd/httpd_ref2sink_bof.result-filte

```

# Research paper

We present our approach and findings of this work in the following research paper: <br>
<strong> [Precise Discovery of More Taint-Style Vulnerabilities in Embedded Firmware](https://ieeexplore.ieee.org/document/10613486) </strong>

*Published in: IEEE Transactions on Dependable and Secure Computing*

If you use SinkTaint in a scientific publication, we would appreciate citations using the following **Bibtex** entry:

```
@article{sinktaint,
  author={Yin, Xiaokang and Cai, Ruijie and Zhu, Xiaoya and Yang, Qichao and Song, Enzhou and Liu, Shengli},
  journal={IEEE Transactions on Dependable and Secure Computing}, 
  title={Precise Discovery of More Taint-Style Vulnerabilities in Embedded Firmware}, 
  year={2025},
  volume={22},
  number={2},
  pages={1365-1382},
  doi={10.1109/TDSC.2024.3434667}
}
```
