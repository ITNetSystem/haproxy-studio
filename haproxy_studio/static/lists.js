/* Shared, client-side navigation for long operator lists. No records are removed. */
(() => {
'use strict';
const states=new Map(),controllers=new WeakMap();let serial=0;
function mount(root,scope){
 const specs=[['.service-list',':scope > .service-item'],['.publication-flows',':scope > .publication-flow'],['.certificate-list',':scope > .panel'],['.route-entry',':scope > .route-flow'],['.table-scroll tbody',':scope > tr']];
 for(const [selector,children] of specs)root.querySelectorAll(selector).forEach((container,index)=>{
  if(controllers.has(container)||container.closest('.wizard-form,.admin-form,.service-tls,.import-results'))return;
  const rows=[...container.querySelectorAll(children)];if(rows.length<=8)return;
  const key=scope+'|'+selector+'|'+index,state=states.get(key)||{page:0,size:8,query:''};states.set(key,state);
  const tools=document.createElement('div'),id='list-filter-'+(++serial);tools.className='list-tools';tools.setAttribute('role','group');tools.setAttribute('aria-label','Поиск и страницы списка');
  tools.innerHTML=`<label for="${id}">Найти в списке<input id="${id}" type="search" placeholder="Название, домен, IP или порт"></label><label>На странице<select data-size><option value="8">8</option><option value="20">20</option><option value="50">50</option><option value="0">Все</option></select></label><span class="list-count" role="status" aria-live="polite"></span><div class="list-pages"><button type="button" data-prev aria-label="Предыдущая страница списка">Назад</button><button type="button" data-next aria-label="Следующая страница списка">Далее</button></div>`;
  const table=container.closest('.table-scroll');if(table)table.before(tools);else if(container.matches('.route-entry'))container.querySelector('summary').after(tools);else container.before(tools);
  const input=tools.querySelector('input'),size=tools.querySelector('select'),count=tools.querySelector('.list-count'),prev=tools.querySelector('[data-prev]'),next=tools.querySelector('[data-next]');input.value=state.query;size.value=String(state.size);if(scope==='routes'&&rows.every(row=>row.hasAttribute('data-search'))){input.closest('label').hidden=true;state.query='';input.value=''}
  const text=rows.map(row=>(row.dataset.search||row.textContent).toLocaleLowerCase('ru'));
  function update(){
   const matching=rows.filter((row,i)=>!row.hidden&&text[i].includes(state.query.toLocaleLowerCase('ru').trim()));
   const pages=state.size?Math.max(1,Math.ceil(matching.length/state.size)):1;state.page=Math.max(0,Math.min(state.page,pages-1));
   const shown=new Set(state.size?matching.slice(state.page*state.size,(state.page+1)*state.size):matching);
   rows.forEach(row=>row.classList.toggle('list-hidden',!shown.has(row)));
   const from=matching.length?(state.size?state.page*state.size:0)+1:0,to=state.size?Math.min((state.page+1)*state.size,matching.length):matching.length;
   count.textContent=`${from}–${to} из ${matching.length}`;prev.disabled=state.page===0;next.disabled=state.page>=pages-1;
  }
  input.addEventListener('input',()=>{state.query=input.value;state.page=0;update()});size.addEventListener('change',()=>{state.size=Number(size.value);state.page=0;update()});
  for(const [button,delta] of [[prev,-1],[next,1]])button.addEventListener('click',()=>{state.page+=delta;update();tools.scrollIntoView({block:'nearest'})});
  controllers.set(container,update);update();
 });
}
function refresh(root){root.querySelectorAll('.service-list,.publication-flows,.certificate-list,.route-entry,.table-scroll tbody').forEach(node=>controllers.get(node)?.())}
window.StudioLists={mount,refresh};
const button=document.getElementById('density');let compact=true;try{compact=localStorage.getItem('studio-density')!=='comfortable'}catch(_){}
function density(){document.body.classList.toggle('compact',compact);if(button){button.setAttribute('aria-pressed',String(compact));button.textContent=compact?'Компактно':'Просторно';button.title='Переключить плотность интерфейса'}}
if(button)button.addEventListener('click',()=>{compact=!compact;density();try{localStorage.setItem('studio-density',compact?'compact':'comfortable')}catch(_){}});density();
})();
