#!/bin/bash

# Comprehensive Disaster Recovery Script for Enterprise Auth Backend
# This script handles complete disaster recovery procedures including database restoration,
# system recovery, and service validation

set -euo pipefail

# Configuration
RECOVERY_TYPE="${1:-full}"  # full, partial, point-in-time
BACKUP_SOURCE="${2:-s3}"    # s3, local, cross-region
RECOVERY_POINT="${3:-latest}" # latest, timestamp, or specific backup ID

# Environment variables
BACKUP_DIR="${BACKUP_DIR:-/backups/database}"
S3_BUCKET="${BACKUP_S3_BUCKET:-}"
S3_CROSS_REGION_BUCKET="${BACKUP_S3_CROSS_REGION_BUCKET:-}"
POSTGRES_HOST="${POSTGRES_HOST:-localhost}"
POSTGRES_PORT="${POSTGRES_PORT:-5432}"
POSTGRES_DB="${POSTGRES_DB:-enterprise_auth}"
POSTGRES_USER="${POSTGRES_USER:-postgres}"
ENCRYPTION_KEY="${BACKUP_ENCRYPTION_KEY:-}"
NOTIFICATION_WEBHOOK="${NOTIFICATION_WEBHOOK:-}"
RECOVERY_LOG_DIR="${RECOVERY_LOG_DIR:-/var/log/disaster-recovery}"
DRY_RUN="${DRY_RUN:-false}"
SKIP_VERIFICATION="${SKIP_VERIFICATION:-false}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Create log directory
mkdir -p "$RECOVERY_LOG_DIR"
RECOVERY_LOG="$RECOVERY_LOG_DIR/disaster_recovery_$(date +%Y%m%d_%H%M%S).log"

# Redirect all output to log file as well
exec > >(tee -a "$RECOVERY_LOG")
exec 2>&1

# Logging functions
log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
}

info() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] INFO: $1${NC}"
}

# Function to send notifications
send_notification() {
    local status="$1"
    local message="$2"
    local details="${3:-}"
    
    if [ -n "$NOTIFICATION_WEBHOOK" ]; then
        local payload="{\"status\": \"$status\", \"message\": \"$message\", \"timestamp\": \"$(date -Iseconds)\", \"recovery_type\": \"$RECOVERY_TYPE\", \"backup_source\": \"$BACKUP_SOURCE\", \"recovery_point\": \"$RECOVERY_POINT\""
        
        if [ -n "$details" ]; then
            payload="${payload}, \"details\": $details"
        fi
        
        payload="${payload}}"
        
        curl -X POST "$NOTIFICATION_WEBHOOK" \
            -H "Content-Type: application/json" \
            -d "$payload" \
            --silent --show-error || warn "Failed to send notification"
    fi
}

# Function to check prerequisites
check_prerequisites() {
    log "Checking disaster recovery prerequisites..."
    
    # Check required tools
    local required_tools=("pg_dump" "pg_restore" "psql" "createdb" "dropdb" "pg_isready" "curl" "aws")
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            error "$tool is not installed"
            send_notification "failed" "Disaster recovery failed: $tool not installed"
            exit 1
        fi
    done
    
    # Check environment variables
    if [ -z "${POSTGRES_PASSWORD:-}" ]; then
        error "POSTGRES_PASSWORD environment variable is required"
        send_notification "failed" "Disaster recovery failed: POSTGRES_PASSWORD not set"
        exit 1
    fi
    
    # Check disk space (require at least 20GB free for recovery operations)
    local available_space=$(df "$BACKUP_DIR" | awk 'NR==2 {print $4}')
    if [ "$available_space" -lt 20971520 ]; then  # 20GB in KB
        error "Insufficient disk space. Available: $(($available_space / 1024 / 1024))GB, Required: 20GB"
        send_notification "failed" "Disaster recovery failed: Insufficient disk space"
        exit 1
    fi
    
    # Check network connectivity for S3 operations
    if [[ "$BACKUP_SOURCE" == "s3" || "$BACKUP_SOURCE" == "cross-region" ]]; then
        if ! aws sts get-caller-identity &>/dev/null; then
            error "AWS credentials not configured or invalid"
            send_notification "failed" "Disaster recovery failed: AWS credentials invalid"
            exit 1
        fi
    fi
    
    log "Prerequisites check passed"
}

# Function to create recovery checkpoint
create_recovery_checkpoint() {
    local checkpoint_name="$1"
    local checkpoint_file="$RECOVERY_LOG_DIR/checkpoint_${checkpoint_name}_$(date +%Y%m%d_%H%M%S).json"
    
    cat > "$checkpoint_file" << EOF
{
  "checkpoint": "$checkpoint_name",
  "timestamp": "$(date -Iseconds)",
  "recovery_type": "$RECOVERY_TYPE",
  "backup_source": "$BACKUP_SOURCE",
  "recovery_point": "$RECOVERY_POINT",
  "database_status": "$(PGPASSWORD="$POSTGRES_PASSWORD" pg_isready -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$POSTGRES_DB" 2>/dev/null && echo "available" || echo "unavailable")",
  "system_status": {
    "disk_space_gb": $(df "$BACKUP_DIR" | awk 'NR==2 {print int($4/1024/1024)}'),
    "load_average": "$(uptime | awk -F'load average:' '{print $2}' | xargs)",
    "memory_usage_percent": $(free | awk 'NR==2{printf "%.2f", $3*100/$2}')
  }
}
EOF
    
    log "Recovery checkpoint created: $checkpoint_file"
}

# Function to find the appropriate backup file
find_backup_file() {
    log "Searching for backup file..."
    local backup_file=""
    
    case "$BACKUP_SOURCE" in
        "s3")
            if [ -z "$S3_BUCKET" ]; then
                error "S3_BUCKET not configured"
                exit 1
            fi
            
            info "Searching S3 bucket: $S3_BUCKET"
            
            if [ "$RECOVERY_POINT" = "latest" ]; then
                backup_file=$(aws s3 ls "s3://$S3_BUCKET/database-backups/" --recursive | sort -k1,2 | tail -1 | awk '{print $4}')
            else
                backup_file=$(aws s3 ls "s3://$S3_BUCKET/database-backups/" --recursive | grep "$RECOVERY_POINT" | head -1 | awk '{print $4}')
            fi
            
            if [ -n "$backup_file" ]; then
                local s3_path="s3://$S3_BUCKET/$backup_file"
                local local_path="$BACKUP_DIR/$(basename "$backup_file")"
                
                log "Downloading backup from S3: $s3_path"
                
                # Get file metadata
                local file_size=$(aws s3api head-object --bucket "$S3_BUCKET" --key "$backup_file" --query 'ContentLength' --output text)
                log "Backup file size: $(numfmt --to=iec $file_size)"
                
                # Download with progress
                aws s3 cp "$s3_path" "$local_path" --no-progress
                
                if [ $? -eq 0 ]; then
                    log "Backup downloaded successfully"
                    backup_file="$local_path"
                else
                 m S3"
               1
                fi
            fi
            ;;
        "cross-region")
            if [ -z "$S3_CROSS_REGION_BUCKET" ]; then
                error "S3_CROSS_REGION_BUCKET not configur"
                exit 1
            fi
            
            info "Searching cross-region S3 bucket: $S3_CROSS_REGION_BUCKET"
            
            if [ "$RECOVERY_POINT" = "latest" ]; then
                backup_file=$(aws s3 ls "s3://$S3_CROSS_REGION_BUCKET/database-backuprint $4}')
            else
                backup_file=$(aws s3 ls "s3://$S3_CROSS_REG$4}')
  fi

            if [hen
                
           
                
                log "Downloapath"
          ss
                
                if [ $? -eq
                    log "Bacy"
                    backup_file="
          else
            on S3"
                    exit 1
                fi
            fi
            ;;
        "l")
            info "Searching
            
           then
         1)
            else
                backup_file=$(
           fi
            ;;
    esac
    
    if [ -
    
mainunctionmain f
# Run 1
fi
it ex   "
 ired is requbleonment variaSWORD envirPOSTGRES_PASor "en
    err-}" ]; thD:WORS_PASSOSTGREz "${Ples
if [ -iabart vironmennvk required e Chec 1
fi

#exit
    43000"240115_1_backup_20rise_authterps-region encrosint-in-time e $0 po=truERIFICATIONP_Vcho "  SKIst"
    ell s3 late $0 fu_RUN=true DRYho "   ec  143000"
40115_ local 202 partial$0o "     echatest"
 full s3 l $0 o "     ech"
les:echo "Examp   
 o ""
    echery)"r-recovteas/dis/var/logefault: ogs (d lrecoveryy for rector   Di_DIR      VERY_LOGo "  RECO
    echse)"ult: falon (defaverificatiecovery p rN        SkiVERIFICATIO SKIP_o "    echfalse)"
 lt: (defau changes thout actual wiorm dry runPerf           RUN       o "  DRY_ech"
    ionsnotificatr ook URL foWebhHOOK     ION_WEB NOTIFICAT  echo " ckups"
  bay for ion ke  EncryptPTION_KEY  NCRYCKUP_E "  BA   echocket"
 gion S3 buss-reroKET  CEGION_BUC_CROSS_RS3 "  BACKUP_"
    echokupsor backet f   S3 bucBUCKET      S3_  BACKUP_echo "se)"
    bata/backups/dalt: faurectory (deackup di      B         CKUP_DIRBAecho "    
  required)"ord (swase pasDatab      PASSWORD   TGRES_ POS  echo " "
  Variables:ent  "Environmho
    eccho ""
    eest]"ault: latd) [def_i|backup|timestampst(lateint ecovery pot   Ry_poin"  recover"
    echo s3]) [default: egioncross-ral|oc3|l(s of backup  Sourceup_source    back echo " ime)"
   point-in-tartial||p (fullof recoverye ype    Typcovery_t "  re echo
   Arguments:""  echo ""
  echo "
    ry_point]ve[recoce] urup_so[back_type> coveryage: $0 <re   echo "Us; then
  ]$# -eq 0[ ents
if icient argumffnsuusage if i Show 

#es
}porary_filup_tem clean  
     
    fi
e": $exit_cod exit code failed withrocess recovery pter" "Disasailed"fcation _notifisend
        ailed""fort covery_repreerate_        gen"
edailery_ft "recovpoiny_checkcover_re     create"
   exit_code $code: with exit ss failedce prorecoveryster ror "Disa      erSIGINT
   130 is en  #ne 130 ]; th" -ode"$exit_c0 ] && [ ode -ne it_c$ex
    if [  $1
   de=exit_col    locaxit() {
 nup_on_e
clea}
LOG"
VERY_og: $RECO lcovery  log "Redate)"
  d at: $(eteCompl log "   fi
    
      exit 1
 led"
     ai fr recovery "Disasteled"faiion "d_notificaten"
        s === Failedveryr RecoDisaste== "=error 
        ""failedry_report recovegenerate_       e
   elsly"
  successfulompleted ry cver reco"Disaste" pletedtion "comend_notifica        s"
sfully ===uccespleted Scovery Comer ResastDig "===       lo"
  rt "successecovery_reponerate_r   ge     ue ]; then
ss" = tr_succeeryrecov  if [ "$
  ortep rate finaler
    # Geni
     fi
    f   
    uccessful"dered snsi coecovery isbut rd, faile tests recoveryme post-   warn "So          else
   
    s passed"stry teecoveg "Post-rlo         ; then
   estscovery_t_post_reif run        ue ]; then
s" = truccesecovery_s  if [ "$rry tests
  coven post-re   # Ru
    
 s
    fiservicestart_        reue ]; then
ess" = trry_succoveec "$r if [ces
   art serviest  
    # R
    fi
       fise
   s=faly_succesrecover         d"
   aileification fvery ver reco"Databaserror    e       else
   "
       ssedon pa verificaticoveryDatabase re"g       lo      
covery; thenverify_re     if    then
  = true ];uccess"covery_s if [ "$re  overy
 # Verify rec   
   fi
    alse
  cess=fy_succover    re  ailed"
  recovery fse taba error "Da   
    e
    elssfully"ed succesmpletcovery cose reatabalog "D      then
   ile";p_fbacku"$ry abase_recovem_datrforf peery
    ie recovabasatform d # Per    
   p_file"
ckuba"$_backup yzeanalup
    ckze ba# Analy
    
    kup_file")"$bacbackup ss_decompreile=$(_fup  back")
  ckup_file$baackup "=$(decrypt_bkup_file bac  ile)
 ind_backup_f$(f_file=
    backupkup_file bacocalfile
    lbackup nd prepare    # Find a
 tes
    erequisick_pr
    chetesprerequisiheck   
    # CXIT
  it $?' En_exp 'cleanup_o    traification
final notcleanup and ap for Tr
    # true
    s=ry_succesveocal reco
    l
    rted" process stater recovery" "Disas "startedicationend_notif"
    sovery_startint "recry_checkpote_recove crea  
   ate)"
  : $(dStarted at log "   Y_RUN"
Dry Run: $DRog "    lY_POINT"
OVER Point: $RECery "Recov    log
CE"UP_SOUR$BACKource: p Slog "Backu
    "PERECOVERY_TY Type: $"Recovery  log ry ==="
  ster Recovend Disauth Backeise Aterpr=== En
    log "ain() {process
mry ecove r}

# Maineaned up"
 cl files"Temporary    
    log true
 v/null ||/derm -f 2>0 | xargs -1-n sort | head -type f | t_*.json" checkpoin-name "" RG_DI$RECOVERY_LO   find "last 10)
 s (keep int fileeckpomove old ch 
    # Re  fi
   rue
  ull || t>/dev/nete 2 f -del -typeERY_LOG"OVr "$REC" -neweup_*backise_auth_*_rpre "ente -namACKUP_DIR"  find "$B
      " ]]; thenoss-regionCE" == "cr_SOUR"$BACKUP|| " E" == "s3OURC$BACKUP_S if [[ "very
   is recoded for thre downloay weles if thebackup fiownloaded  d   # Remove  
 es..."
   filtemporaryp ng uCleani    log "{
_files() p_temporaryiles
cleanuorary fmpleanup teunction to c F"
}

#rt_fileeponerated: $rort gevery rep  log "Reco
    }
EOF
  "[]")
|| echo v/null -s '.' 2>/deq  \; | jexec cat {}_LOG" - "$RECOVERYwer.json" -nent_*e "checkpoiIR" -namOVERY_LOG_DEC $(find "$Rnts":oikpchecG",
  "LORECOVERY_ile": "$"log_f,
  "
  }m)(uname -ure": "$hitectrc"a",
    $(uname -r)l": "rne,
    "kee -s)"nam$(u"os": ")",
    "$(hostnamename": 
    "hosto": {em_inf
  "syst"
  },DBRES_": "$POSTGse   "databaT",
 OR_PGRES "$POST  "port":HOST",
  TGRES_": "$POS    "host
 {e":databas,
  "RIFICATION": $SKIP_VEerificationkip_v
  "s_RUN,": $DRY  "dry_runime",
": "$end_tnd_timee",
  "etart_timme": "$sart_tiT",
  "stECOVERY_POIN"$R_point": veryco"re 
 CE",KUP_SOUR "$BACup_source":
  "backRY_TYPE","$RECOVEery_type": recovs",
  "statu"$"status": log)",
  RY_LOG" .COVEe "$REbasenam": "$("recovery_id
  
{ EOF_file" <<report> "$cat 
    
    n")know| echo "un | -d '[]']' | tr.*\-o '\[p  | greY_LOG"OVER-1 "$RECme=$(head rt_ti   local sta)
  -Iseconds$(dateend_time=ocal 
    l"
    %H%M%S).json +%Y%m%d_(dateery_report_$ecovG_DIR/rOVERY_LO"$RECle=fieport_
    local r"$1"l status= {
    loca()ortry_repecoveate_rport
generrecovery reo generate  Function tfi
}

#  turn 1
    re"
      ledests fairecovery tl post-Some criticaror "   er
         elsen 0
tur
        re"ssedry tests pacove-reposttical ri "All c        logthen
= true ]; s" _succeserall "$ov    if [te"
    
complests_ecovery_tent "post_rery_checkpoi_recovatecre     
   ne
  do
  "tatusest_se: $t$test_nam   log "      2)
 cut -d: -f" | result(echo "$atus=$ test_st    local: -f1)
    cut -desult" | "$r$(echo e=al test_nam      loc; do
  ]}"s[@{test_resultsult in "$
    for res:" resultovery testPost-rec "
    logltsresust y of temar 
    # Sumfi
   RN")
    vity:WAonnectiery_c"cel_results+=(stte        al)"
iticed (non-crtest fail processing  taskgroundBack     warn "   se
  el")
  SStivity:PAnec_con=("celeryest_results+       tsed"
 asg test pocessinnd task pr"Backgrou      log 1; then
  >& 2/dev/nullt" > _endpoin$celery_testtime 10 "f -s --max-l -f cur
    ilery/"0/health/ce:800lhost//locahttp:_endpoint="ry_testlocal celeg..."
    sk processinground tating backog "Tes
    lprocessingd task ackgrounest 5: B  # T 
     fi
   
 y:WARN")_connectivits+=("cache_result       test
 )"itical(non-cr failed sty tenectivit"Cache con     warn  else
   S")
   tivity:PASonnec+=("cache_ct_resultstes
        sed"t pastesy ctivitnne co"Cache log     then
   l 2>&1;  > /dev/nulint"est_endpocache_t"$time 10 s --max- -url -fif che/"
    0/health/cac800host:://localnt="httpst_endpoil cache_te
    loca"ivity...he connect cactinglog "Tes
    dis)y (Reivitache connect 4: C Test   # 
 i
   e
    fcess=falsoverall_suc    ")
    int:FAILpo"auth_ends+=(sult_re      test)"
  nseth_respoTTP $aust failed (Hndpoint te eonticatir "Authen    erro  else
    
  int:PASS")"auth_endpo_results+=(test       ponse)"
 th_res$auassed (HTTP st p endpoint tetionuthenticaog "A
        l; then]]0-9][0-9]$ [45][" =~ ^nse$auth_respo [[ " 
    if")
   cho "000v/null || e' 2>/de -d '{}tion/json"pe: applicatent-Ty"Connt" -H $auth_endpoiOST "0 -X P-time 1max--ttp_code}" "%{hull -w  -o /dev/nse=$(curl -srespon local auth_"
   loginpi/v1/auth/t:8000/ap://localhosttint="hh_endpoocal aut   l
 .."dpoints.enntication ting autheg "Tes    lot
oinion endpatic: Authent # Test 3
    
   fi=false
    ssucceerall_sov      FAIL")
  onnectivity:"db_csults+=(st_re      te"
  t failed tesity connectivbaser "Data       erro
    else
 ty:PASS")b_connectivi("dresults+=     test_"
   edss pasttivity teectabase conng "Da
        lon2>&1; the/null " > /devointt_endpesb_time 10 "$dx-t --maurl -f -s
    if ch/db/"healt00/host:80localttp://"ht=_endpoinal db_test
    loc."..licationity from appe connectivbastag da"Testin  log on
  catifrom applinectivity tabase cont 2: Da# Tes    
    
done))
    tempt++        ((ati
     f
             fi0
   1eple         s     
  ..."n 10 secondsng ied, retryimpts failax_attempt/$mtteempt $ack att chelth  info "Hea       e
                elsalse
   s=fsucces  overall_         L")
     AIk:Falth_chects+=("heest_resul         t
        attempts"max_attemptster $ck failed afHealth che "or        errn
        pts ]; thetemax_atpt -eq $mattemf [ $          ilse
       ek
   brea           ASS")
 alth_check:Phe=("s+test_result          pt)"
  ttemt $ad (attempk passechecHealth log "            2>&1; then
ev/null " > /dpoint"$health_endtime 10 ax---m -f -s rlf cu        ipts ]; do
 $max_attem$attempt -lewhile [ 
    
    mpt=1te    local atpts=60
max_attem
    local /health/"8000//localhost:http:"point=ndlth_ecal hea   looint..."
 alth endp"Testing helog   
  dpoint en1: Healthest    # T    
 true
ll_success=al overa)
    locesults=( test_r
    local fi
     0
   eturn        rests"
ry tcove-ren postd ruRUN: WoulY g "DR        lo]; then
"true" _RUN" = [ "$DRYif   
    
  s_start"overy_test"post_recint ckpoovery_chereate_rec    csts..."
covery tepost-remprehensive Running co   log "
 y_tests() {vert_reco
run_possecovery testnsive post-rcompreheto run unction 
# F"
}
t_completee_restarservicnt "ery_checkpoite_recovrea   
    c fi
 art"
   estice rpping servted, skitem detecstration sysche oro container"N  warn 
      
    elsessfully"rted succes restaviceCompose serDocker g "   loeat
      celery-bt web celerympose restarker-co        doc.."
 services.ker Composearting Docst "Re log      ull; then
 ev/nose &> /dcompdocker-ommand -v f c    eliully"
sfed succesices restartes servrnetg "Kube  lo  
      one
         d
            fi     ut"
within timeoeady  rd to becomement faileloynt $dep "Deployme       warn         else
          y"
  readployment is yment $deDeplog "      lo
           thenut=300s;th --timeoterprise-aunt" -n enymedeploment/"$tus deploy rollout staubectl       if k"
     ntyme $deploready:nt to be ploymede for aiting "W     log    ; do
   ]}"ents[@eploymn "${dployment i for dedy
       e reants to bloymer dep   # Wait fo             
    done

    e-authrprisente-n " eploymentt/"$d deploymenestartrollout rbectl     ku
        "ent $deploym deployment:estarting"R   log          do
 ts[@]}";menloy"${depyment in plo    for de  
    ")
      -beath-celeryrprise-auttey" "ene-auth-celerrprisb" "ente-wee-authiss=("enterprdeployment   local  
        "
    ...entstes deploymKubernetarting g "Res    lothen
    ; nullinfo &>/dev/er-bectl clustkull && /dev/nu &> bectland -v ku    if commubernetes
ing in K If runn  #    
  0
    fi
  return es"
      ication servapplict tarresould DRY RUN: W"    log 
     thentrue" ]; = "_RUN""$DRYf [ 
    
    iart"e_restart_st "servickpoint_checcoveryate_re  cre."
  ervices..ation sg applic"Restartin   log ices() {
 tart_servvices
resication serart applrestion to }

# Funct

    fiturn 1       re failed"
 cationifivery verse reco"Databaror 
        er  elseurn 0
         ret
 e"ion_completficatoint "vericheckpe_recovery_ creat"
       n successfulificatiovery verreco "Database    loghen
     sful" ]; t"test_succest" = ry_resul "$test_queif [   )
    
 -d ' 'l | tr dev/nul;" 2>/essful''test_succ"SELECT   -t -c 
      " \STGRES_DB$PO  -d "    ER" \
  $POSTGRES_US  -U "     
 S_PORT" \STGRE"$PO        -p \
GRES_HOST" ST   -h "$PO
     \RD" psql ES_PASSWORD="$POSTGRSSWOlt=$(PGPAesu_query_rst tes
    localerationatabase opsic dest ba   # T
   fi
    rn 1
  tu      re}"
  s[*]ble_ta ${missingssing: tables mi"Critical error en
       gt 0 ]; thtables[@]} -issing_   if [ ${#mone
    
     d
      fie")
  +=("$tablssing_tables   mi       then
   "t" ];ts" !=  [ "$exis  if   
         ')
   d '');" | tr - = '$table_nameablelic' AND tchema = 'pube_s tablREHEes Wschema.tablormation_FROM infELECT  EXISTS (Sc "SELECT-t -     
       " \TGRES_DBOS"$P    -d \
        " ER_USRESU "$POSTG           -\
 _PORT" $POSTGRES  -p "      " \
    TGRES_HOSTOS-h "$P          psql \
  " ORDPASSW$POSTGRES_D="WOR=$(PGPASStsxis e   local    "; do
 ]}les[@_tabcaln "${critir table i 
    foles=()
   issing_tabocal m  l")
  essionons_users"sessin" permissio" "auth_"auth_role" erprofilesers_us("ules=tical_tab cri
    locals existbletatical fy cri  # Veri   
  
 ion_count"ess: $s Sessions  log " "
  user_count  Users: $
    log "_count" $tableables:og "  T
    l results:"rificatione veog "Databas l   ")
    
cho "0 ' ' || e -dll | tr>/dev/nu" 2session;s_useronsessiT(*) FROM SELECT COUNc " -t -
       DB" \RES_STG"$PO     -d 
   S_USER" \U "$POSTGRE   -
     T" \S_POR"$POSTGRE -p\
        ES_HOST" $POSTGR "
        -h" psql \PASSWORDGRES_ORD="$POSTt=$(PGPASSWsession_coun
    local     ")
o "0 || ech ' '| tr -dv/null ;" 2>/de_userprofileOM users(*) FR COUNTELECT -c "S       -tDB" \
 POSTGRES_  -d "$    SER" \
  TGRES_UU "$POS        -ORT" \
_P$POSTGRES -p "\
       HOST" $POSTGRES_ -h " \
       WORD" psqlPASS"$POSTGRES_RD=PGPASSWOer_count=$(local us  
    
  d ' ') tr -" |blic';= 'pua ble_schem WHERE taleschema.tabation_snform FROM iNT(*)ECT COUSEL" -c 
        -tES_DB" \ "$POSTGR   -d  " \
   S_USERGRE -U "$POST       \
GRES_PORT" "$POST     -p " \
   _HOSTTGRES$POS"-h     l \
    D" psqS_PASSWORTGRERD="$POSSSWOt=$(PGPAble_coun  local taics
  atistase stdatab# Get 
    
     fi  turn 1
        rebase"
 d datarevecoto reect nnot connrror "Ca   e
      then";BTGRES_D-d "$POSSER" STGRES_U"$PO" -U STGRES_PORT" -p "$POOSTRES_H"$POSTGy -h adreD" pg_isWORSSTGRES_PA="$POSRD! PGPASSWO
    if tivitye connecbas# Check data
    
      fi0
   return   
     "recoveryase tabverify daN: Would  "DRY RUog        ln
ue" ]; the" = "trUN"$DRY_R
    if [     tart"
tion_srificakpoint "vehecry_cate_recove    creovery..."
se rectaba daifying "Ver
    log    fi
     0
eturn   r
     sted" requeification asery verng recovippi "Sk        logthen
"true" ]; ICATION" = P_VERIFf [ "$SKIy() {
    irecovery
verify_over verify recction to
}

# Fun 1
    fi   exit
     xit_code}"e_e$restor": xit_code\" "{\"ey failedoverase recDatabd" ""faileication end_notif    sd"
    very_failecoabase_repoint "datheckcovery_ce_recreat        xit_code"
re_e: $restoth exit codeled wicovery fai"Database re    error     else
"
    _duration} $restorends\":uration_seco\"d"{mpleted" covery coDatabase reress" "on "progtiicaif   send_note"
     etery_complase_recovt "databpoincovery_checkcreate_re    
    ds"onn} sece_duration ${restorccessfully icompleted sue recovery asg "Datab       lo
 then]; eq 0 _exit_code -[ $restore  
    if time))
  tart_ restore_snd_time -re_estoon=$((reratie_duestorocal r+%s)
    le=$(date nd_timstore_eal re   loc 
 
   _code=$?restore_exitlocal e_pid
     $restor  
    wait  done
  ep 30
    slens"
      onnectioions: $cve connect Actiprogress...re in restoabase "Dat  info ")
      ho "0|| ectr -d ' ' /dev/null | B';" 2>TGRES_D'$POStname = ity WHERE da_activM pg_statnt(*) FROSELECT cou "     -t -c       ES_DB" \
GR-d "$POST      \
      RES_USER" POSTG"$   -U      
    " \_PORTESTGR-p "$POS         " \
   TGRES_HOST -h "$POS
           " psql \_PASSWORD"$POSTGRESPGPASSWORD=tions=$(necocal con       l do
 ull;v/n2>/de_pid -0 $restoree kill s
    whilore progres restorit 
    # Mon  e_pid=$!
 estorcal r lo
    
   kup_file" &  "$bac     \
 bs=4 jo --
       s \ --if-exist \
       an       --cleileges \
   --no-priv   wner \
       --no-oose \
          --verb
  " \OSTGRES_DB$P "        -dUSER" \
GRES_U "$POST
        -PORT" \ES_ "$POSTGR    -p
    \ES_HOST" TGR"$POS       -h re \
 " pg_restoSWORDRES_PAS="$POSTGORDSWGPAS
    Pe +%s)
    me=$(dat_tiestore_start   local rkup..."
  bacatabase fromng drilog "Restobackup
    om e fr# Restor 
    esac
      ;;
           
  dlingtamp hanfic timesith speci wbutecovery  full r to  # Similar        
  overy..."ase recatabin-time ding point-erformog "P    l
        e")-timint-in       "po
      ;;   
    sedatabarop the on't dvery, we dal recotipar   # For 
         ry..."covebase rertial dataorming palog "Perf          ial")
        "part  ;
      ;     S_DB"
 "$POSTGRE        
         \"GRES_USER  -U "$POST            
  RT" \OSTGRES_PO$P      -p "
          \HOST" RES_STGh "$PO         -     tedb \
  eacrSWORD" POSTGRES_PAS"$PASSWORD=       PG    base..."
 atating new drea log "C        
   atabaseate new d  # Cre
                  ..."
    ontinuing, cot existse does n "Databaull || logdev/n 2>/DB"S_"$POSTGRE                R" \
ES_USE"$POSTGR -U          " \
      ES_PORT"$POSTGR   -p            " \
  GRES_HOST-h "$POST              
  dropdb \" S_PASSWORDREORD="$POSTGSW       PGPAS..."
     basedataxisting g eog "Droppin    le
        atabas dop existing        # Dr             
   rue
 || t 2>/dev/null_pid();"kendacg_b<> pD pid  ANES_DB'TGR= '$POSname ERE dat_activity WH pg_statFROMpid) ckend(nate_batermipg_-c "SELECT             \
     postgres -d                _USER" \
 "$POSTGRES          -U \
      GRES_PORT"OSTp "$P         - \
       _HOST"STGRES-h "$PO                psql \
 ASSWORD"S_P"$POSTGREGPASSWORD=       P
     "ons...connectibase e datactiverminating aog "T  l          ctions
ive conneerminate act    # T       
          
   ry..."se recovell databang fu "Performi    log        )
l"   "ful" in
     TYPERY_e "$RECOVEas  c types
  veryt recoerene diffandl   
    # H_backup
 pre_recovery    create_ry backup
recove pre-ate  # Cre   
     fi
 n 0
      returile"
   ckup_fle: $ba with fie recoverybasrm datauld perfoRY RUN: Wo"Dg lo   then
      ]; = "true"RY_RUN"  if [ "$D    
   ")\"}"
p_filekuac "$b(basename"$: \"kup_file\bac{\"" "tartedry se recove "Databas"on "startedficatiotisend_nrt"
    overy_stase_recabapoint "daty_checke_recovercreat..."
    e recoverydatabasng rti   log "Sta
   e="$1"
  _filal backup loc{
   very() _recoabasem_daterforecovery
pase rrform databto pe# Function 
}

fi
     backup"covery-reing preble, skipp accessi notase databrrentg "Cu  lolse
       efi
   "
        recoveryinuing with , but contiledup fabackcovery "Pre-re     warn      
         else"
 t -f1)" | cubackupcovery_e_re "$pre: $(du -hy backup sizPre-recover"     log        up"
y_backver_reco$preted:  backup crearecovery"Pre-      log n
       the$? -eq 0 ];    if [      
       mp_pid
 $du  wait   
          
        donep 10
  slee           fi
            size"
ent size: $ess... Currprogrn y backup iovere-recfo "Pr   in             o "0")
|| ech| cut -f1 null up" 2>/dev/ackcovery_b_re$pre=$(du -h "l sizeloca             then
    p" ];ckuecovery_ba$pre_rif [ -f "        do
    l;  2>/dev/nul_piddumple kill -0 $       whi progress
 itor backup   # Mon
             $!
ump_pid=     local d   
   
     kup" &very_bacecoile="$pre_r --f        \
   verbose           --tom \
  cus --format=
           " \POSTGRES_DB     -d "$
        \"ES_USERSTGRU "$PO -
           " \TGRES_PORT "$POS          -pT" \
  RES_HOS-h "$POSTG          dump \
  " pg_SWORDOSTGRES_PASRD="$P  PGPASSWO     
 
        S).sql"_%H%M%%Y%m%dup_$(date +ckecovery_bae_rIR/pr$BACKUP_Dbackup="e_recovery_  local pr   
   henev/null; t" 2>/dRES_DB$POSTG-d "S_USER" STGRE "$PO" -URES_PORT -p "$POSTGT"S_HOSGREOST -h "$Pg_isreadyPASSWORD" pS_TGRE"$POSWORD= if PGPASSessible
   nd is accs aistabase exatk if d  # Chec  
  "
  ...atabase current d backup oferyrecovng pre-tig "Crea   lo
    
 
    fi0n  retur   
     backup"recoverycreate pre-d WoulN: DRY RUog "        ln
rue" ]; the = "tY_RUN"$DR [ "    ifackup() {
very_bate_pre_reco
creupbackery ecove pre-r to creation
# Funct
"
}nutesmid_minutes imateime: $eststoration ttimated reog "Es
    l 
   fi
    minutes=1stimated_     e; then
   lt 1 ]es -nutted_mi [ $estima
    ifer minutee: 100MB patstim# Rough emb / 100))  ile_size_=$((ftesed_minul estimat    loca1)
ut -f" | cackup_file"$b -m =$(du_size_mbl file
    locaizen file se based ooration timimate rest  # Est  
  i
  
    format"QL custom fas PostgreSized  not recognatkup form"Bacrn        wae
  elsdone
       
      $line"      log "   ine; do
    -r lreade  | whilnfo"ckup_i$ba "   echow:"
     evietents prckup con  log "Ba     20)
 ll | head -nuv/>/de 2ackup_file"st "$b--li(pg_restore =$ backup_info       localformation
 inGet backup       #     
  mat"
    ustom forL cgreSQat: Postckup formlog "Baen
        ump"; thatabase dustom dreSQL ctgos"Pp -q ree" | gfil$backup_ "   if fileat dump
 stom formostgreSQL cus a Pif it'    # Check  

   ."le..up fiyzing back"Anal log    1"
    
e="$_filackup
    local bkup() {ze_bacle
analy backup fito analyzeion 
# Funct}
i

    f"_fileho "$backup ec       
    else
        fi   exit 1
       "
  failedssion mpre decoupck"Baerror           e
       els   ile"
_fressedho "$decomp     ec      
 f1)"e" | cut -ild_fressecomp(du -h "$de: $ile sizecompressed f"De     log        fully"
successressed ckup decomp  log "Ba     hen
     e" ]; tmpressed_fils "$deco [ - -eq 0 ] &&f [ $?      i     
    fi
     
    le"ssed_fimpre"$decoup_file" > p -c "$back     gunzi     lse
  
        ee"essed_fil> "$decompr_file" ackupc "$b pigz -d -  
         /null; then&> /devigz and -v pmmif co   ble
      availampression ifllel decoparase pigz for  # U        
    gz}"
   e%.ckup_filbale="${ompressed_fical dec lo
       ckup..."ssing bag "Decompre     lo; then
    == *.gz ]]ile"$backup_f   if [[ "
    
 $1"kup_file=" baclocal    kup() {
compress_bac
deackupess becomprction to d
# Fun fi
}
"
   up_fileecho "$backe
        fi
    els
          exit 1        "
   or invalidle is emptyecrypted fir "D erro          else
        "
 ile$decrypted_f "       echo  
   -f1)"" | cut efil"$decrypted_ -h : $(due sized filteryplog "Dec           en
 ; thed_file" ]"$decrypt -s      if [ile
   pted fify decry      # Ver
     i
         f
       exit 1
         " failedionp decryptkuBacr "       errolse
      e  "
     S-256-CBC)ssfully (AE succecryptedp de"Backu   log         en
 dev/null; th>/ 2TION_KEY" "$ENCRYP" -kpted_filet "$decry -oue"up_fil"$backd -salt -in cbc --256-aespenssl enc -      elif oCM)"
  (AES-256-Gccessfully ed sukup decryptog "Bac         l then
   ull;>/dev/nEY" 2N_K"$ENCRYPTIOe" -k pted_fildecry"$" -out ile_fn "$backuplt -i -sacm -d-256-gssl enc -aes     if opens
   n methodt encryptiofferenry di      # T     
    %.enc}"
 _filee="${backupilpted_f decryocal l       p..."
ckuypting ba"Decrog        l
        
 
        fi   exit 1
         rovided" pn keyo encryptiot nencrypted buBackup is or "  err         ; then
 N_KEY" ]ENCRYPTIOf [ -z "$   ien
     ; th== *.enc ]]e" backup_fil[[ "$ 
    if $1"
   "p_file=ckul baloca    ) {
p(ecrypt_backuif needed
drypt backup o dec Function t
#ile"
}
"$backup_f echo  
   
    fi
   ksum": $checsum checkp file MD5"Backulog 
         -d' ' -f1)" | cut$backup_file(md5sum "ksum=$  local chec
      /null; thensum &> /devand -v md5
    if commty integri fileerify backup  # V 
    
 cut -f1)" | le"ckup_fibau -h "$ize: $(d file supacklog "B"
    le_fiuple: $backkup fiUsing bac
    log "i
    
    f      exit 1
  t found"up file noBackfailed: covery aster re"Dis" ailedn "fationotific       send__POINT"
 : $RECOVERYintrecovery pond for fouot p file nku error "Bac   