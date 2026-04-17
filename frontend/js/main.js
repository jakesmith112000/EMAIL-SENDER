// Shared drag & drop handlers
function dragOver(e) {
    e.preventDefault();
    e.currentTarget.classList.add('drag-over');
}
function dragLeave(e) {
    e.currentTarget.classList.remove('drag-over');
}

// Process recipient file (CSV/TXT)
function processRecipientFile(file, textareaId, badgeId) {
    const reader = new FileReader();
    reader.onload = (ev) => {
        let content = ev.target.result;
        let emails = [];
        if (file.name.endsWith('.csv')) {
            content.split('\n').forEach(line => {
                let email = line.split(',')[0].trim();
                if (email && email.includes('@')) emails.push(email);
            });
        } else {
            emails = content.split('\n').filter(l => l.trim() && l.includes('@')).map(l => l.trim());
        }
        const textarea = document.getElementById(textareaId);
        if (textarea) {
            const existing = textarea.value.split('\n').filter(l => l.trim());
            const all = [...new Set([...existing, ...emails])];
            textarea.value = all.join('\n');
        }
        const badge = document.getElementById(badgeId);
        if (badge) {
            badge.textContent = `✅ ${emails.length} recipients loaded`;
            badge.style.display = 'inline-block';
        }
        const zone = e.currentTarget;
        zone.classList.add('success');
        setTimeout(() => zone.classList.remove('success'), 1500);
    };
    reader.readAsText(file);
}

// Process HTML file drop
function processHtmlFile(file, textareaId, badgeId) {
    const reader = new FileReader();
    reader.onload = (ev) => {
        document.getElementById(textareaId).value = ev.target.result;
        const badge = document.getElementById(badgeId);
        if (badge) {
            badge.textContent = `✅ ${file.name} loaded`;
            badge.style.display = 'inline-block';
        }
        const zone = e.currentTarget;
        zone.classList.add('success');
        setTimeout(() => zone.classList.remove('success'), 1500);
        // Refresh preview if active
        const previewPane = document.getElementById('previewTab');
        if (previewPane && previewPane.classList.contains('active')) {
            document.getElementById('previewContent').innerHTML = ev.target.result;
        }
    };
    reader.readAsText(file);
}

// Spam check
async function checkSpam(textareaId, resultDivId) {
    const html = document.getElementById(textareaId).value;
    if (!html) {
        alert('Please write or load HTML content first');
        return;
    }
    const resultDiv = document.getElementById(resultDivId);
    resultDiv.innerHTML = '<div style="text-align:center">🔍 Checking spam score...</div>';
    try {
        const res = await fetch('/api/spamcheck', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ html: html })
        });
        const data = await res.json();
        if (data.success) {
            const score = parseFloat(data.score);
            let color = '#10b981';
            let level = 'Low Risk';
            if (score > 5) { color = '#ef4444'; level = 'High Risk'; }
            else if (score > 2) { color = '#f59e0b'; level = 'Medium Risk'; }
            resultDiv.innerHTML = `
                <div style="text-align:center; margin-bottom:1rem">
                    <div style="font-size:2rem; font-weight:bold; color:${color}">${data.score}/10</div>
                    <div>${level}</div>
                </div>
                <div><strong>${data.rules.length} rules triggered:</strong></div>
                ${data.rules.map(r => `<div class="rule-item"><strong style="color:#ef4444">+${r.score}</strong> - ${r.description}</div>`).join('')}
            `;
        } else {
            resultDiv.innerHTML = `<div class="alert alert-error">Spam check failed: ${data.error || 'Unknown error'}</div>`;
        }
    } catch(err) {
        resultDiv.innerHTML = `<div class="alert alert-error">Error: ${err.message}</div>`;
    }
}

// Convert file to base64
function fileToBase64(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(reader.result.split(',')[1]);
        reader.onerror = reject;
        reader.readAsDataURL(file);
    });
}