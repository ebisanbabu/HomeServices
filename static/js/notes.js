(function(){
  function byId(id){ return document.getElementById(id); }
  var modal, content, closeBtn, okBtn;

  function showModal(text){
    if(!modal || !content) return;
    console.debug('notes.js: showModal called');
    if(!content.hasChildNodes()){
      content.textContent = text || '(no notes)';
    }
    modal.style.display = 'flex';
    modal.setAttribute('aria-hidden','false');
  }
  function hideModal(){
    if(!modal) return;
    modal.style.display = 'none';
    modal.setAttribute('aria-hidden','true');
  }

  function onBtnClick(e){
    var btn = e.currentTarget;
    var note = btn.getAttribute('data-note') || '';
    var username = btn.getAttribute('data-username') || '';
    try{
      if(!content) content = byId('noteModalContent');
      if(!content) return;
      content.innerHTML = '';
      var u = document.createElement('div');
      u.style.fontWeight = '600';
      u.style.marginBottom = '6px';
      u.textContent = 'Username: ' + (username || '(unknown)');
      content.appendChild(u);
      var sep = document.createElement('hr');
      content.appendChild(sep);
      var noteEl = document.createElement('div');
      noteEl.style.whiteSpace = 'pre-wrap';
      noteEl.textContent = note || '(no notes)';
      content.appendChild(noteEl);
    }catch(err){ console.error('render note failed', err); }
    try{ console.debug('notes.js: onBtnClick', {note:note, username:username}); showModal(); }catch(err){ console.error('showModal failed', err); }
  }

  document.addEventListener('DOMContentLoaded', function(){
    modal = byId('noteModal');
    content = byId('noteModalContent');
    closeBtn = byId('noteModalClose');
    okBtn = byId('noteModalOk');

    var buttons = document.querySelectorAll('button[data-note]');
    console.debug('notes.js: DOMContentLoaded, buttons found=', buttons.length);
    for(var i=0;i<buttons.length;i++){
      buttons[i].addEventListener('click', onBtnClick);
    }
    if(closeBtn) closeBtn.addEventListener('click', hideModal);
    if(okBtn) okBtn.addEventListener('click', hideModal);
    document.addEventListener('keydown', function(e){ if(e.key==='Escape') hideModal(); });
  });
})();
