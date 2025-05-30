// static/js/app.js

function fetchSystemInfo() {
    fetch('/system_info')
      .then(response => response.json())
      .then(data => {
        document.getElementById('cpu-usage').innerText = data.cpu + '%';
        document.getElementById('mem-usage').innerText = data.memory_percent + '%';
        document.getElementById('disk-usage').innerText = data.disk_percent + '%';
      })
      .catch(err => console.error(err));
  }
  
  // 3초에 한 번씩 데이터 갱신
  setInterval(fetchSystemInfo, 3000);
  
  // 초기 실행
  fetchSystemInfo();
  