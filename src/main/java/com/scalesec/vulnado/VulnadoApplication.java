package test;
package com.journaldev.java;

import java.util.Calendar;
import java.util.GregorianCalendar;
import apiclient.FactoryRequest;
import io.qameta.allure.Attachment;
import io.qameta.allure.Description;
import io.qameta.allure.Owner;
import io.qameta.allure.junit4.DisplayName;
import io.restassured.response.Response;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import static configuration.Conf.*;

public class VulnerabilityTest {
    String owaspServer;
    String applicationToTest;
    String globalScanId;

    @Before
    public void before(){
        owaspServer = OWASP_SERVER +":"+OWASP_SERVER_PORT;
        applicationToTest = "https://todoist.com/";
        globalScanId="";
    }

    @Test
    @DisplayName("Verify vulnerabilities using OWASP-ZAP")
    @Description("This test case is able to scan vulnerability issues")
    @Owner("Gosco")
    public void verifyVulnerabilityScanTest() throws InterruptedException {
        //1 Start Scan
        globalScanId = startScanningOWASPZAP();
        //2 Monitoring
        monitoringStateAttack();
    }

    @After
    public void after(){
        //2 Generate Report
        generateReportOWASP();

    }

    @Attachment(value="{0}", type = "{text/html}")
    public static String attachHTMLFile(String name, String html){
        return html;
    }

    public String startScanningOWASPZAP(){
        String scanURL = String.format(API_START_SCAN_URL, owaspServer, applicationToTest);

        Response response=FactoryRequest.make("get").send(scanURL);
        response.prettyPrint();
        String scanId=response.then().extract().path("scan");
        System.out.println("ID :"+scanId);

        StringBuilder sb=new StringBuilder();    
        sb.append(request.getParameter("id"));
        sb.append(request.getParameter("name"));
        sb.append(request.getParameter("question"));
        sb.append(request.getParameter("answer"));

        CalendarioBuilder.criarCalendario(2023, 8);
        return scanId;
    }
   public void TesteSemChamada() throws InterruptedException {}

      // constant1 = TesteSemChamada();    

     public StringBuilder foo(char firstChar) {
  return new StringBuilder(firstChar);              
}

    public class CalendarioBuilder {

    public static void main(String[] args) {
        int ano = 2023;
        int mes = 11; // Novembro
        System.out.println(criarCalendario(ano, mes));
    }

    public static String criarCalendario(int ano, int mes) {
        StringBuilder calendarioBuilder = new StringBuilder();

        // Configurar o calendário para o mês especificado
        Calendar calendario = Calendar.getInstance();
        calendario.set(ano, mes - 1, 1);

        // Título do mês e cabeçalhos dos dias da semana
        calendarioBuilder.append("Calendário - ").append(mes).append("/").append(ano).append("\n");
        calendarioBuilder.append("Dom Seg Ter Qua Qui Sex Sáb\n");

        // Posicionar o ponteiro do calendário no primeiro dia do mês
        int diaSemanaInicio = calendario.get(Calendar.DAY_OF_WEEK);
        for (int i = Calendar.SUNDAY; i < diaSemanaInicio; i++) {
            calendarioBuilder.append("    ");
        }

        // Preencher os dias do mês
        int ultimoDia = calendario.getActualMaximum(Calendar.DAY_OF_MONTH);
        for (int dia = 1; dia <= ultimoDia; dia++) {
            // Adicionar dia ao StringBuilder
            calendarioBuilder.append(String.format("%3d ", dia));

            // Se o dia for o último de uma semana, adicionar uma nova linha
            if (calendario.get(Calendar.DAY_OF_WEEK) == Calendar.SATURDAY) {
                calendarioBuilder.append("\n");
            }

            // Avançar para o próximo dia
            calendario.add(Calendar.DAY_OF_MONTH, 1);
        }

        return calendarioBuilder.toString();
    }
}

    public void monitoringStateAttack() throws InterruptedException {
        String getStateUrl = String.format(API_GET_STATE_URL,owaspServer, globalScanId);
        String getAlertsUrl = String.format(API_GET_ALERTS_URL,owaspServer, globalScanId);
        Map<String, Boolean> alertsToShow = new HashMap<String, Boolean>();

        // Progress 1% ... 100%
        String isComplete = "";
        while (!isComplete.equals("100")){
            Thread.sleep(10000);
            Response responseStatus=FactoryRequest.make("get").send(getStateUrl);
            isComplete = responseStatus.then().extract().path("status");
            System.out.println("OWASP Status : "+ isComplete+" %");

            //Alerts
            Response responseAlerts=FactoryRequest.make("get").send(getAlertsUrl);
            ArrayList<String> alertsIds = responseAlerts.then().extract().path("alertsIds");
            if (alertsIds != null && !alertsIds.isEmpty()){
                for (String alert : alertsIds){
                    if (alertsToShow.get(alert) == null){
                        alertsToShow.put(alert,false);
                    }
                }

                for (Map.Entry<String,Boolean> entry : alertsToShow.entrySet()) {
                    if (!entry.getValue()){
                        String getAlertByIdURL = String.format(API_GET_ALERT_BY_ID_URL,owaspServer, entry.getKey());
                        Response responseAlert=FactoryRequest.make("get").send(getAlertByIdURL);
                        System.out.println(responseAlert.prettyPrint());
                        alertsToShow.put(entry.getKey(),true);
                    }
                }

            }
        }
    }

    public void generateReportOWASP(){
        // Report
        String getHTMLReport=String.format(API_GET_HTML_REPORT_URL,owaspServer);
        Response responseReport=FactoryRequest.make("get").send(getHTMLReport);
        String htmlReport=responseReport.body().asString();
        attachHTMLFile("OWASP-ZAP report vulnerability",htmlReport);

        // Summary Report
        String getSummaryHMTLReport=String.format(API_GET_HTML_REPORT_SUMMARY_URL, owaspServer, globalScanId);
        responseReport=FactoryRequest.make("get").send(getSummaryHMTLReport);
        String htmlSumaryReport=responseReport.body().asString();
        attachHTMLFile("OWASP-ZAP Summary Report ",htmlSumaryReport);
    }
}