// static/js/main.js
document.addEventListener('DOMContentLoaded', function () {
  // Wire choose image links
  document.querySelectorAll('.choose-image-link').forEach(function (link) {
    link.addEventListener('click', function (ev) {
      ev.preventDefault();
      const studentId = link.dataset.studentId;
      const input = document.querySelector('.student-image-input[data-student-id="' + studentId + '"]');
      input.click();
    });
  });

  // When file chosen, show Upload button and preview thumbnail
  document.querySelectorAll('.student-image-input').forEach(function (input) {
    input.addEventListener('change', function (ev) {
      const studentId = input.dataset.studentId;
      const saveBtn = document.querySelector('.save-image-btn[data-student-id="' + studentId + '"]');
      saveBtn.style.display = 'inline-block';
      // Optionally preview: create temp image preview in row
      const file = input.files[0];
      if (file) {
        const reader = new FileReader();
        reader.onload = function (e) {
          // append preview or replace existing
          let img = document.querySelector('#row-' + studentId + ' img.preview-temp');
          if (!img) {
            img = document.createElement('img');
            img.classList.add('preview-temp');
            img.style.width = '50px';
            img.style.marginRight = '8px';
            document.querySelector('#row-' + studentId + ' td').prepend(img);
          }
          img.src = e.target.result;
        };
        reader.readAsDataURL(file);
      }
    });
  });

  // Upload to server
  document.querySelectorAll('.save-image-btn').forEach(function (btn) {
    btn.addEventListener('click', function () {
      const studentId = btn.dataset.studentId;
      const input = document.querySelector('.student-image-input[data-student-id="' + studentId + '"]');
      if (!input.files.length) return alert('Choose an image first');
      const file = input.files[0];
      const formData = new FormData();
      formData.append('image', file);
      fetch('/admin/upload_image/' + studentId, {
        method: 'POST',
        body: formData
      }).then(r => r.json()).then(data => {
        if (data.success) {
          alert('Image uploaded');
          btn.style.display = 'none';
          // replace thumbnail actual src
          const imgEl = document.querySelector('#row-' + studentId + ' img.preview-temp');
          if (imgEl) {
            imgEl.src = '/uploads/' + data.filename;
          } else {
            // add final image
            const img = document.createElement('img');
            img.src = '/uploads/' + data.filename;
            img.width = 50;
            document.querySelector('#row-' + studentId + ' td').prepend(img);
          }
        } else {
          alert('Upload failed: ' + data.message);
        }
      }).catch(err => alert('Upload error: ' + err));
    });
  });

  // Generate button: show modal and populate fields
  const modalEl = document.getElementById('idModal');
  const bootstrapModal = new bootstrap.Modal(modalEl);

  document.querySelectorAll('.generate-btn').forEach(function (btn) {
    btn.addEventListener('click', function () {
      const s = JSON.parse(btn.getAttribute('data-student'));
      // populate modal fields
      document.getElementById('card-name').innerText = s.name || '';
      document.getElementById('card-dept').innerText = s.department || '';
      document.getElementById('card-roll').innerText = s.roll_no || '';
      document.getElementById('card-emergency').innerText = s.emergency_contact || 'N/A';
      document.getElementById('card-address').innerText = s.address || 'N/A';
      // image: prefer preview-temp (local selected) else server image
      const previewImg = document.querySelector('#row-' + s.id + ' img.preview-temp');
      const photoEl = document.getElementById('card-photo');
      if (previewImg) {
        photoEl.src = previewImg.src;
      } else if (s.image) {
        photoEl.src = '/uploads/' + s.image;
      } else {
        photoEl.src = '';
      }
      bootstrapModal.show();
    });
  });

  // Download PDF from modal: use html2canvas + jsPDF
  document.getElementById('downloadPdfBtn').addEventListener('click', async function () {
    const container = document.getElementById('idCardPreview');

    // We'll generate two pages: front then back
    const { jsPDF } = window.jspdf;

    // Create new jsPDF with A4 landscape orientation for wider cards, or portrait as you like
    const pdf = new jsPDF({ unit: 'px', format: 'a4' });

    // Capture front
    const front = document.getElementById('id-card-front');
    await html2canvas(front, { scale: 2 }).then(canvas => {
      const imgData = canvas.toDataURL('image/png');
      // fit to PDF page width (keep margin)
      const pageWidth = pdf.internal.pageSize.getWidth();
      const pageHeight = pdf.internal.pageSize.getHeight();
      const imgProps = pdf.getImageProperties(imgData);
      const imgWidth = pageWidth - 40;
      const imgHeight = (imgProps.height * imgWidth) / imgProps.width;
      pdf.addImage(imgData, 'PNG', 20, 20, imgWidth, imgHeight);
    });

    // Add second page for back
    pdf.addPage();
    const back = document.getElementById('id-card-back');
    await html2canvas(back, { scale: 2 }).then(canvas => {
      const imgData = canvas.toDataURL('image/png');
      const pageWidth = pdf.internal.pageSize.getWidth();
      const imgProps = pdf.getImageProperties(imgData);
      const imgWidth = pageWidth - 40;
      const imgHeight = (imgProps.height * imgWidth) / imgProps.width;
      pdf.addImage(imgData, 'PNG', 20, 20, imgWidth, imgHeight);
    });

    const filename = 'id_card_' + Date.now() + '.pdf';
    pdf.save(filename);
  });

});
